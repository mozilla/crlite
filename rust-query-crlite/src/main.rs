//! # rust-query-crlite
//!
extern crate base64;
extern crate bincode;
extern crate byteorder;
extern crate clap;
extern crate der_parser;
extern crate hex;
extern crate log;
extern crate num_bigint;
extern crate pem;
extern crate reqwest;
extern crate rust_cascade;
extern crate rustls;
extern crate serde;
extern crate sha2;
extern crate stderrlog;
extern crate x509_parser;

use byteorder::{LittleEndian, ReadBytesExt};
use clap::Parser;
use der_parser::oid;
use log::*;
use rust_cascade::Cascade;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::io::prelude::Write;
use std::io::{BufReader, Read};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use x509_parser::prelude::*;

const ICA_LIST_URL: &str =
    "https://ccadb.my.salesforce-sites.com/mozilla/MozillaIntermediateCertsCSVReport";

const STAGE_ATTACH_URL: &str = "https://firefox-settings-attachments.cdn.allizom.org/";
const STAGE_URL: &str = "https://firefox.settings.services.allizom.org/v1/buckets/security-state-staging/collections/cert-revocations/records";

const PROD_ATTACH_URL: &str = "https://firefox-settings-attachments.cdn.mozilla.net/";
const PROD_URL: &str = "https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/cert-revocations/records";

const COVERAGE_SERIALIZATION_VERSION: u8 = 1;
const COVERAGE_V1_ENTRY_BYTES: usize = 48;

const ENROLLMENT_SERIALIZATION_VERSION: u8 = 1;
const ENROLLMENT_V1_ENTRY_BYTES: usize = 32;

#[rustfmt::skip]
const OID_SCT_EXTENSION: &der_parser::Oid = &oid!(1.3.6.1.4.1.11129.2.4.2);

type CRLiteKey = Vec<u8>;
type DERCert = Vec<u8>;
type EnrollmentKey = Vec<u8>;
type IssuerDN = Vec<u8>;
type IssuerSPKIHash = Vec<u8>;
type LogID = Vec<u8>;

fn crlite_key(issuer_spki_hash: &[u8], serial: &[u8]) -> CRLiteKey {
    let mut key = issuer_spki_hash.to_vec();
    key.extend_from_slice(serial);
    key
}

fn enrollment_key(issuer_dn: &[u8], issuer_spki: &[u8]) -> EnrollmentKey {
    let mut hasher = Sha256::new();
    hasher.update(issuer_dn);
    hasher.update(issuer_spki);
    hasher.finalize().to_vec()
}

#[derive(Debug)]
enum Status {
    Expired,
    Good,
    NotCovered,
    NotEnrolled,
    Revoked,
}

#[derive(Debug)]
struct CRLiteDBError {
    message: String,
}

impl<T: Display> From<T> for CRLiteDBError {
    fn from(err: T) -> CRLiteDBError {
        CRLiteDBError {
            message: format!("{}", err),
        }
    }
}

#[allow(non_snake_case)]
#[derive(Deserialize)]
struct CRLiteCoverage {
    logID: String,
    maxTimestamp: u64,
    minTimestamp: u64,
}

#[derive(Deserialize)]
struct RemoteSettingsData {
    data: Vec<JsonRecord>,
}

#[allow(non_snake_case)]
#[derive(Deserialize)]
struct JsonRecord {
    attachment: JsonRecordAttachment,
    coverage: Option<Vec<CRLiteCoverage>>,
    enrolledIssuers: Option<Vec<String>>,
    incremental: bool,
    channel: Option<CRLiteFilterChannel>,
}

#[derive(Deserialize)]
struct JsonRecordAttachment {
    hash: String,
    location: String,
    size: u64,
}

fn update_intermediates(int_dir: &Path) -> Result<(), CRLiteDBError> {
    let intermediates_path = int_dir.join("crlite.intermediates");

    info!("Fetching {}", ICA_LIST_URL);
    let intermediates_bytes = &reqwest::blocking::get(ICA_LIST_URL)
        .map_err(|_| CRLiteDBError::from("could not fetch CCADB report"))?
        .bytes()
        .map_err(|_| CRLiteDBError::from("could not read CCADB report"))?;

    let intermediates = Intermediates::from_ccadb_csv(intermediates_bytes)
        .map_err(|_| CRLiteDBError::from("cannot parse CCADB report"))?;

    let encoded_intermediates = intermediates.encode()?;

    std::fs::write(intermediates_path, &encoded_intermediates)?;

    Ok(())
}

fn update_db(
    db_dir: &Path,
    attachment_url: &str,
    collection_url: &str,
    channel: &CRLiteFilterChannel,
) -> Result<(), CRLiteDBError> {
    let filter_path = db_dir.join("crlite.filter");
    let stash_path = db_dir.join("crlite.stash");
    let enrollment_path = db_dir.join("crlite.enrollment");
    let coverage_path = db_dir.join("crlite.coverage");

    info!("Fetching remote settings data from {}", collection_url);
    let records: RemoteSettingsData = reqwest::blocking::get(collection_url)
        .map_err(|_| CRLiteDBError::from("could not fetch remote settings collection"))?
        .json()
        .map_err(|_| CRLiteDBError::from("could not read remote settings data"))?;

    let (stashes, full_filters): (Vec<&JsonRecord>, Vec<&JsonRecord>) = records
        .data
        .iter()
        .filter(|x| x.channel.unwrap_or_default() == *channel)
        .partition(|x| x.incremental);

    if full_filters.len() != 1 {
        return Err(CRLiteDBError::from(
            "number of full filters found in remote settings is not 1",
        ));
    }

    let full_filter = full_filters[0];

    let mut filter_needs_update = true;
    let mut stash_needs_update = true;

    // Skip filter update if existing filter has expected sha256 hash.
    if filter_path.exists() {
        let expected_digest = hex::decode(&full_filter.attachment.hash)
            .map_err(|_| CRLiteDBError::from("full filter digest corrupted"))?;
        let mut hasher = Sha256::new();
        hasher.update(std::fs::read(&filter_path)?);
        if expected_digest == hasher.finalize().as_slice() {
            filter_needs_update = false;
        }
    }

    // Skip stash update if the filter is fresh and the stash on disk has the expected size.
    // (We can't easily check the provided hashes since we concatenate stashes on disk.)
    let expected_stash_size = stashes.iter().fold(0, |x, y| x + y.attachment.size);
    let stash_metadata = std::fs::metadata(&stash_path);
    if !filter_needs_update
        && stash_path.exists()
        && stash_metadata.is_ok()
        && stash_metadata.unwrap().len() == expected_stash_size
    {
        stash_needs_update = false
    }

    if !filter_needs_update {
        info!("Filter is up to date");
    } else {
        let enrolled_issuers = match &full_filter.enrolledIssuers {
            Some(enrolled_issuers) => enrolled_issuers,
            _ => return Err(CRLiteDBError::from("missing enrollment data")),
        };

        let mut enrollment_bytes = vec![ENROLLMENT_SERIALIZATION_VERSION];
        for b64_issuer_id in enrolled_issuers {
            let issuer_id = match base64::decode(&b64_issuer_id) {
                Ok(issuer_id) if issuer_id.len() == 32 => issuer_id,
                _ => return Err(CRLiteDBError::from("malformed enrollment data")),
            };
            enrollment_bytes.extend_from_slice(&issuer_id);
        }

        let coverage = match &full_filter.coverage {
            Some(coverage) => coverage,
            _ => return Err(CRLiteDBError::from("missing coverage data")),
        };

        let mut coverage_bytes = vec![COVERAGE_SERIALIZATION_VERSION];
        for entry in coverage {
            let log_id = match base64::decode(&entry.logID) {
                Ok(log_id) if log_id.len() == 32 => log_id,
                _ => return Err(CRLiteDBError::from("malformed coverage data")),
            };
            coverage_bytes.extend_from_slice(&log_id);
            coverage_bytes.extend_from_slice(&entry.minTimestamp.to_le_bytes());
            coverage_bytes.extend_from_slice(&entry.maxTimestamp.to_le_bytes());
        }

        let full_filter_url = format!("{}{}", attachment_url, full_filter.attachment.location);
        info!("Fetching filter from {}", full_filter_url);
        let filter_bytes = &reqwest::blocking::get(full_filter_url)
            .map_err(|_| CRLiteDBError::from("could not fetch full filter"))?
            .bytes()
            .map_err(|_| CRLiteDBError::from("could not read full filter"))?;

        let expected_digest = hex::decode(&full_filter.attachment.hash)
            .map_err(|_| CRLiteDBError::from("full filter digest corrupted"))?;
        let mut hasher = Sha256::new();
        hasher.update(filter_bytes);
        if expected_digest != hasher.finalize().as_slice() {
            return Err(CRLiteDBError::from("full filter digest mismatch"));
        }

        std::fs::write(&enrollment_path, &enrollment_bytes)?;
        std::fs::write(&coverage_path, &coverage_bytes)?;
        std::fs::write(&filter_path, &filter_bytes)?;
    }

    if !stash_needs_update {
        info!("Stash is up to date");
    } else {
        let mut stash_bytes = vec![];
        let mut hasher = Sha256::new();
        for entry in stashes {
            let stash_url = format!("{}{}", attachment_url, entry.attachment.location);
            info!("Fetching {}", stash_url);
            let stash = &reqwest::blocking::get(stash_url)
                .map_err(|_| CRLiteDBError::from("could not fetch stash"))?
                .bytes()
                .map_err(|_| CRLiteDBError::from("could not read stash"))?;
            hasher.update(stash);
            let digest = hasher.finalize_reset();
            match hex::decode(&entry.attachment.hash) {
                Ok(expected_digest) if expected_digest == digest.as_slice() => (),
                _ => return Err(CRLiteDBError::from("stash digest mismatch")),
            }
            stash_bytes.extend_from_slice(stash);
        }

        std::fs::write(&stash_path, &stash_bytes)?;
    }

    Ok(())
}

struct CRLiteDB {
    filter: Cascade,
    stash: Stash,
    coverage: Coverage,
    enrollment: Enrollment,
    intermediates: Intermediates,
}
impl CRLiteDB {
    fn load(db_dir: &Path) -> Result<Self, CRLiteDBError> {
        let filter_path = db_dir.join("crlite.filter");
        let stash_path = db_dir.join("crlite.stash");
        let enrollment_path = db_dir.join("crlite.enrollment");
        let coverage_path = db_dir.join("crlite.coverage");
        let intermediates_path = db_dir.join("crlite.intermediates");

        let filter_bytes = std::fs::read(filter_path)?;
        let filter = Cascade::from_bytes(filter_bytes)?
            .ok_or_else(|| CRLiteDBError::from("empty filter"))?;

        let stash_bytes = std::fs::read(stash_path)?;
        let stash = Stash::from_bytes(&stash_bytes)?;

        let coverage_bytes = std::fs::read(coverage_path)?;
        let coverage = Coverage::from_bytes(&coverage_bytes)?;

        let enrollment_bytes = std::fs::read(enrollment_path)?;
        let enrollment = Enrollment::from_bytes(&enrollment_bytes)?;

        // If db_dir is the security_state directory of a firefox profile,
        // then it will have all of the files except for crlite.intermediates.
        // It might be useful to inspect a firefox profile without updating
        // the other files. So let's fetch the intermediates file if it's the
        // only one missing.
        if !intermediates_path.exists() {
            update_intermediates(db_dir)?;
        }

        let intermediates_bytes = std::fs::read(intermediates_path)?;
        let intermediates = Intermediates::from_bincode(&intermediates_bytes)?;

        Ok(CRLiteDB {
            filter,
            stash,
            coverage,
            enrollment,
            intermediates,
        })
    }

    pub fn query(&self, cert: &X509Certificate) -> Status {
        let issuer_dn = &cert.tbs_certificate.issuer;
        let serial = cert.tbs_certificate.raw_serial();

        debug!("Issuer DN: {}", cert.tbs_certificate.issuer);
        debug!("Serial number: {}", hex::encode(&serial));

        let issuer_spki = match self.intermediates.lookup_issuer_spki(cert) {
            Some(issuer_spki) => issuer_spki.raw,
            _ => return Status::NotEnrolled,
        };

        let mut hasher = Sha256::new();
        hasher.update(&issuer_spki);
        let issuer_spki_hash = hasher.finalize().to_vec();

        debug!("Issuer SPKI hash: {}", hex::encode(&issuer_spki_hash));

        let enrollment_key = enrollment_key(issuer_dn.as_raw(), issuer_spki);
        debug!("Issuer enrollment key: {}", base64::encode(&enrollment_key));

        if !self.enrollment.contains(&enrollment_key) {
            return Status::NotEnrolled;
        }

        if !self.coverage.contains(cert) {
            return Status::NotCovered;
        }

        if self.stash.has(&issuer_spki_hash, &serial) {
            return Status::Revoked;
        }

        // An expired certificate, even if enrolled and covered, might
        // not be included in the filter.
        if !cert.tbs_certificate.validity.is_valid() {
            return Status::Expired;
        }

        let crlite_key = crlite_key(&issuer_spki_hash, &serial);
        if self.filter.has(crlite_key) {
            Status::Revoked
        } else {
            Status::Good
        }
    }
}

struct Stash(HashMap<IssuerSPKIHash, HashSet<CRLiteKey>>);
impl Stash {
    fn has(&self, issuer_spki_hash: &[u8], serial: &[u8]) -> bool {
        self.0
            .get(issuer_spki_hash)
            .map_or(false, |x| x.contains(serial))
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CRLiteDBError> {
        let mut reader = BufReader::new(bytes);
        let mut stash = HashMap::new();
        while let Ok(num_serials) = reader.read_u32::<LittleEndian>() {
            let issuer_spki_hash_len = reader.read_u8()?;
            let mut issuer_spki_hash = vec![0; issuer_spki_hash_len as usize];
            reader.read_exact(&mut issuer_spki_hash)?;
            let serials = stash.entry(issuer_spki_hash).or_insert_with(HashSet::new);
            for _ in 0..num_serials {
                let serial_len = reader.read_u8()?;
                let mut serial = vec![0; serial_len as usize];
                reader.read_exact(&mut serial)?;
                let _ = serials.insert(serial);
            }
        }
        Ok(Stash(stash))
    }
}

struct Coverage(HashMap<LogID, (u64, u64)>);
impl Coverage {
    fn from_bytes(bytes: &[u8]) -> Result<Self, CRLiteDBError> {
        let mut reader = BufReader::new(bytes);
        if (bytes.len() - 1) % COVERAGE_V1_ENTRY_BYTES != 0 {
            return Err(CRLiteDBError::from("truncated CRLite coverage file"));
        }
        let count = (bytes.len() - 1) / COVERAGE_V1_ENTRY_BYTES;
        match reader.read_u8() {
            Ok(COVERAGE_SERIALIZATION_VERSION) => (),
            _ => return Err(CRLiteDBError::from("unknown CRLite coverage version")),
        }
        let mut coverage = HashMap::new();
        for _ in 0..count {
            let mut coverage_entry = [0u8; COVERAGE_V1_ENTRY_BYTES];
            match reader.read_exact(&mut coverage_entry) {
                Ok(()) => (),
                _ => return Err(CRLiteDBError::from("truncated CRLite coverage file")),
            };
            let log_id = &coverage_entry[0..32];
            let min_timestamp = match (&coverage_entry[32..40]).read_u64::<LittleEndian>() {
                Ok(value) => value,
                _ => return Err(CRLiteDBError::from("truncated CRLite coverage file")),
            };
            let max_timestamp = match (&coverage_entry[40..48]).read_u64::<LittleEndian>() {
                Ok(value) => value,
                _ => return Err(CRLiteDBError::from("truncated CRLite coverage file")),
            };
            coverage.insert(log_id.to_vec(), (min_timestamp, max_timestamp));
        }
        Ok(Coverage(coverage))
    }

    fn contains(&self, cert: &X509Certificate) -> bool {
        let sct_extension = match cert.tbs_certificate.get_extension_unique(OID_SCT_EXTENSION) {
            Ok(Some(sct_extension)) => sct_extension,
            _ => return false,
        };
        let scts = match sct_extension.parsed_extension() {
            ParsedExtension::SCT(scts) => scts,
            _ => return false,
        };
        for sct in scts.iter() {
            if let Some((min, max)) = self.0.get(sct.id.key_id.as_ref()) {
                if *min <= sct.timestamp && sct.timestamp <= *max {
                    debug!(
                        "Logged at {} by enrolled log {}",
                        sct.timestamp,
                        base64::encode(sct.id.key_id)
                    );
                    return true;
                }
            }
        }
        false
    }
}

struct Enrollment(HashSet<EnrollmentKey>);
impl Enrollment {
    fn from_bytes(bytes: &[u8]) -> Result<Self, CRLiteDBError> {
        let mut enrollment = HashSet::new();
        let mut reader = BufReader::new(bytes);
        match reader.read_u8() {
            Ok(ENROLLMENT_SERIALIZATION_VERSION) => (),
            _ => return Err(CRLiteDBError::from("unknown CRLite enrollment version")),
        }
        if (bytes.len() - 1) % ENROLLMENT_V1_ENTRY_BYTES != 0 {
            return Err(CRLiteDBError::from("truncted CRLite enrollment file"));
        }
        let enrollment_count = (bytes.len() - 1) / ENROLLMENT_V1_ENTRY_BYTES;
        for _ in 0..enrollment_count {
            let mut enrollment_entry = [0u8; ENROLLMENT_V1_ENTRY_BYTES];
            match reader.read_exact(&mut enrollment_entry) {
                Ok(()) => (),
                _ => return Err(CRLiteDBError::from("truncted CRLite enrollment file")),
            };
            enrollment.insert(enrollment_entry.to_vec());
        }
        Ok(Enrollment(enrollment))
    }

    fn contains(&self, enrollment_key: &[u8]) -> bool {
        self.0.contains(enrollment_key)
    }
}

struct Intermediates(HashMap<IssuerDN, Vec<DERCert>>);
impl Intermediates {
    fn new() -> Self {
        Intermediates(HashMap::new())
    }

    fn from_ccadb_csv(bytes: &[u8]) -> Result<Self, CRLiteDBError> {
        // XXX: The CCADB report is a CSV file where the last entry in each logical line is a PEM
        //      encoded cert. Unfortunately the newlines in the PEM encoding are not escaped, so
        //      the logical line is split over several actual lines. Fortunately the pem crate is
        //      happy to ignore content surrounding PEM data.
        let list = pem::parse_many(bytes)
            .map_err(|_| CRLiteDBError::from("error reading CCADB report"))?;

        let mut intermediates = Intermediates::new();
        for der in list {
            if let Ok((_, cert)) = X509Certificate::from_der(&der.contents) {
                let name = cert.tbs_certificate.subject.as_raw();
                intermediates
                    .0
                    .entry(name.to_vec())
                    .or_insert_with(Vec::new)
                    .push(der.contents);
            } else {
                return Err(CRLiteDBError::from("error reading CCADB report"));
            }
        }
        Ok(intermediates)
    }

    fn from_bincode(bytes: &[u8]) -> Result<Intermediates, CRLiteDBError> {
        let inner = bincode::deserialize(bytes)
            .map_err(|_| CRLiteDBError::from("could not deserialize bincoded intermediates"))?;
        Ok(Intermediates(inner))
    }

    fn encode(&self) -> Result<Vec<u8>, CRLiteDBError> {
        bincode::serialize(&self.0)
            .map_err(|_| CRLiteDBError::from("could not serialize intermediates"))
    }

    fn lookup_issuer_spki(&self, cert: &X509Certificate) -> Option<SubjectPublicKeyInfo> {
        let issuer_dn = cert.tbs_certificate.issuer.as_raw();
        if let Some(der_issuer_certs) = self.0.get(issuer_dn) {
            let parsed_issuer_certs = der_issuer_certs
                .iter()
                .filter_map(|x| X509Certificate::from_der(x).ok());
            for (_, issuer) in parsed_issuer_certs {
                let issuer_spki = issuer.tbs_certificate.subject_pki;
                if cert.verify_signature(Some(&issuer_spki)).is_ok() {
                    return Some(issuer_spki);
                }
            }
        }
        None
    }
}

struct AcceptAllCertsVerifier;
impl rustls::client::ServerCertVerifier for AcceptAllCertsVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

fn signoff(db: &CRLiteDB, host_file_url: &str) -> Result<CmdResult, CRLiteDBError> {
    let host_file = reqwest::blocking::get(host_file_url)
        .map_err(|_| CRLiteDBError::from("could not fetch hosts file"))?
        .text()
        .map_err(|_| CRLiteDBError::from("could not read hosts file"))?;

    let hosts: Vec<&str> = host_file
        .lines()
        .map(|line| line.trim())
        .filter(|line| !(line.starts_with('#') || line.is_empty()))
        .collect();

    query_https_hosts(db, &hosts)
}

fn query_https_hosts(db: &CRLiteDB, hosts: &[&str]) -> Result<CmdResult, CRLiteDBError> {
    let mut found_revoked_certs = false;

    let config = Arc::new(
        rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(AcceptAllCertsVerifier))
            .with_no_client_auth(),
    );

    for host in hosts.iter() {
        if CmdResult::SomeRevoked == query_https_host(db, host, Arc::clone(&config))? {
            found_revoked_certs = true;
        }
    }

    match found_revoked_certs {
        true => Ok(CmdResult::SomeRevoked),
        false => Ok(CmdResult::NoneRevoked),
    }
}

fn query_https_host(
    db: &CRLiteDB,
    host: &str,
    tls_config: Arc<rustls::ClientConfig>,
) -> Result<CmdResult, CRLiteDBError> {
    let (host, port) = host.rsplit_once(':').unwrap_or((host, "443"));
    let port: u16 = port
        .parse()
        .map_err(|_| CRLiteDBError::from(format!("{}: malformed host port", host)))?;
    let addrs = (String::from(host), port)
        .to_socket_addrs()
        .map_err(|e| CRLiteDBError::from(format!("could not lookup {}: {}", host, e)))?;
    for addr in addrs.as_ref() {
        match query_https_addr(db, host, addr, Arc::clone(&tls_config)) {
            Ok(result) => return Ok(result),
            Err(e) => warn!("{}", e.message),
        }
        // Some servers consistently reset our first TLS connection. Try again!
        match query_https_addr(db, host, addr, Arc::clone(&tls_config)) {
            Ok(result) => return Ok(result),
            Err(_) => (),
        }
    }
    // None of the addresses for this host worked
    return Err(CRLiteDBError::from(format!(
        "could not obtain cert for {}",
        host
    )));
}

fn query_https_addr(
    db: &CRLiteDB,
    host: &str,
    addr: &SocketAddr,
    tls_config: Arc<rustls::ClientConfig>,
) -> Result<CmdResult, CRLiteDBError> {
    let server_name = rustls::ServerName::try_from(host)
        .map_err(|_| CRLiteDBError::from(format!("invalid DNS name: {}", host)))?;

    let mut conn = rustls::ClientConnection::new(Arc::clone(&tls_config), server_name)
        .map_err(|e| CRLiteDBError::from(format!("{}: tls error: {}", host, e)))?;

    let mut sock = TcpStream::connect(addr)
        .map_err(|e| CRLiteDBError::from(format!("{}: tcp error: {}", host, e)))?;

    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.flush() // finish the handshake
        .map_err(|e| CRLiteDBError::from(format!("{}: tls error: {}", host, e)))?;

    let certs = conn
        .peer_certificates()
        .ok_or_else(|| CRLiteDBError::from("no peer certificates"))?;
    let (_, cert) = X509Certificate::from_der(certs[0].as_ref())
        .map_err(|_| CRLiteDBError::from("could not parse certificate"))?;

    debug!("Loaded certificate from {}", host);
    let status = db.query(&cert);
    match status {
        Status::Expired => warn!("{} {:?}", host, status),
        Status::Good => info!("{} {:?}", host, status),
        Status::NotCovered => warn!("{} {:?}", host, status),
        Status::NotEnrolled => warn!("{} {:?}", host, status),
        Status::Revoked => error!("{} {:?}", host, status),
    }
    match status {
        Status::Revoked => Ok(CmdResult::SomeRevoked),
        _ => Ok(CmdResult::NoneRevoked),
    }
}

fn query_certs(db: &CRLiteDB, files: &[PathBuf]) -> Result<CmdResult, CRLiteDBError> {
    let mut found_revoked_certs = false;
    for file in files {
        if !file.exists() {
            warn!("File does not exist: {}", file.display());
            continue;
        }
        let input = match std::fs::read(&file) {
            Ok(input) => {
                debug!("Loaded certificate from {}", file.display());
                input
            }
            Err(_) => {
                warn!("Could not read file: {}", file.display());
                continue;
            }
        };
        let der_cert = match pem::parse(&input) {
            Ok(pem_cert) => pem_cert.contents,
            _ => input,
        };
        if let Ok((_, cert)) = X509Certificate::from_der(&der_cert) {
            let status = db.query(&cert);
            match status {
                Status::Expired => warn!("{} {:?}", file.display(), status),
                Status::Good => info!("{} {:?}", file.display(), status),
                Status::NotCovered => warn!("{} {:?}", file.display(), status),
                Status::NotEnrolled => warn!("{} {:?}", file.display(), status),
                Status::Revoked => {
                    found_revoked_certs = true;
                    error!("{} {:?}", file.display(), status);
                }
            }
        }
    }
    match found_revoked_certs {
        true => Ok(CmdResult::SomeRevoked),
        false => Ok(CmdResult::NoneRevoked),
    }
}

/// A standalone tool for querying a Firefox CRLite database.
///
/// Subcommands exit with code 0 if none of the queried certificates are known to be revoked and
/// with code 1 otherwise. An exit code of 0 might mean that the certificate's issuer is not
/// enrolled or that the certificate is not covered by the filter.  Additional information is
/// logged to stderr.
#[derive(Parser)]
struct Cli {
    /// Download a new CRLite filter and associated metadata from Firefox Remote Settings.
    #[clap(long, arg_enum)]
    update: Option<RemoteSettingsInstance>,

    /// CRLite filter channel
    #[clap(long, value_enum, default_value = "all")]
    channel: CRLiteFilterChannel,

    /// CRLite directory e.g. <firefox profile>/security_state/.
    #[clap(short, long, parse(from_os_str), default_value = "./crlite_db/")]
    db: PathBuf,

    /// Verbosity. -v => warning, -vv => info, -vvv => debug.
    #[clap(short = 'v', parse(from_occurrences))]
    verbose: usize,

    #[clap(subcommand)]
    command: Subcommand,
}

#[derive(clap::ValueEnum, Copy, Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum CRLiteFilterChannel {
    #[default]
    All,
    Specified,
    Priority,
}

#[derive(Clone, clap::ArgEnum)]
enum RemoteSettingsInstance {
    Prod,
    Stage,
    Dev,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Query certificates from TLS handshakes to one or more hosts.
    Https { hosts: Vec<String> },
    /// Fetch a list of https hosts from `host_file_url`, obtain a certificate from each host, and
    /// query each certificate.
    Signoff { host_file_url: String },
    /// Query DER or PEM encoded certificates from one or more files.
    X509 { files: Vec<PathBuf> },
}

#[derive(PartialEq)]
enum CmdResult {
    SomeRevoked,
    NoneRevoked,
}

fn main() {
    let args = Cli::parse();

    stderrlog::new()
        .module(module_path!())
        .verbosity(args.verbose)
        .init()
        .unwrap();

    if std::fs::create_dir_all(&args.db).is_err() {
        error!("Could not create directory: {}", args.db.display());
        std::process::exit(1);
    }

    if args.update.is_some() {
        let (attachment_url, collection_url) = match args.update.unwrap() {
            RemoteSettingsInstance::Dev => (STAGE_ATTACH_URL, STAGE_URL),
            RemoteSettingsInstance::Stage => (STAGE_ATTACH_URL, STAGE_URL),
            RemoteSettingsInstance::Prod => (PROD_ATTACH_URL, PROD_URL),
        };

        if let Err(e) = update_db(&args.db, attachment_url, collection_url, &args.channel) {
            error!("{}", e.message);
            std::process::exit(1);
        }
    }

    if !(args.db.join("crlite.filter").exists()
        && args.db.join("crlite.stash").exists()
        && args.db.join("crlite.enrollment").exists()
        && args.db.join("crlite.coverage").exists())
    {
        error!("CRLite DB is incomplete. Use --update [prod | stage] to populate");
        std::process::exit(1);
    }

    let db = match CRLiteDB::load(&args.db) {
        Ok(db) => db,
        Err(e) => {
            error!("Error loading CRLite DB: {}", e.message);
            std::process::exit(1);
        }
    };

    let result = match args.command {
        Subcommand::Signoff { ref host_file_url } => signoff(&db, host_file_url),
        Subcommand::Https { ref hosts } => {
            let hosts: Vec<&str> = hosts.iter().map(|x| x.as_str()).collect();
            query_https_hosts(&db, &hosts)
        }
        Subcommand::X509 { ref files } => query_certs(&db, files),
    };

    match result {
        Ok(CmdResult::NoneRevoked) => std::process::exit(0),
        Ok(CmdResult::SomeRevoked) => std::process::exit(1),
        Err(e) => {
            error!("{}", e.message);
            std::process::exit(1)
        }
    }
}
