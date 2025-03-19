//! # rust-query-crlite
//!
extern crate base64;
extern crate bincode;
extern crate byteorder;
extern crate clap;
extern crate clubcard;
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

use clap::Parser;
use clubcard_crlite::{CRLiteClubcard, CRLiteStatus};
use der_parser::oid;
use log::*;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fmt::Display;
use std::io::prelude::Write;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use x509_parser::prelude::*;

use base64::prelude::*;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};

const ICA_LIST_URL: &str =
    "https://ccadb.my.salesforce-sites.com/mozilla/MozillaIntermediateCertsCSVReport";

const STAGE_ATTACH_URL: &str = "https://firefox-settings-attachments.cdn.allizom.org/";
const STAGE_URL: &str =
    "https://firefox.settings.services.allizom.org/v1/buckets/security-state-staging/collections/";

const PROD_ATTACH_URL: &str = "https://firefox-settings-attachments.cdn.mozilla.net/";
const PROD_URL: &str =
    "https://firefox.settings.services.mozilla.com/v1/buckets/security-state-staging/collections/";

#[rustfmt::skip]
const OID_SCT_EXTENSION: &der_parser::Oid = &oid!(1.3.6.1.4.1.11129.2.4.2);

type IssuerDN = Vec<u8>;
type DERCert = Vec<u8>;

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

#[derive(Deserialize)]
struct CertRevCollection {
    data: Vec<CertRevRecord>,
}

#[allow(non_snake_case)]
#[derive(Deserialize)]
struct CertRevRecord {
    attachment: CertRevRecordAttachment,
    incremental: bool,
    channel: Option<CRLiteFilterChannel>,
}

#[derive(Deserialize)]
struct CertRevRecordAttachment {
    hash: String,
    filename: String,
    location: String,
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
    base_url: &str,
    channel: &CRLiteFilterChannel,
) -> Result<(), CRLiteDBError> {
    info!(
        "Fetching cert-revocations records from remote settings {}",
        base_url
    );
    let cert_rev_records: CertRevCollection =
        reqwest::blocking::get(base_url.to_owned() + "cert-revocations/records")
            .map_err(|_| CRLiteDBError::from("could not fetch remote settings collection"))?
            .json()
            .map_err(|_| CRLiteDBError::from("could not read remote settings data"))?;

    let filters: Vec<&CertRevRecord> = cert_rev_records
        .data
        .iter()
        .filter(|x| x.channel.unwrap_or_default() == *channel)
        .collect();

    if filters.iter().filter(|x| !x.incremental).count() != 1 {
        return Err(CRLiteDBError::from(
            "number of full filters found in remote settings is not 1",
        ));
    }

    let expected_filenames: HashSet<OsString> = filters
        .iter()
        .map(|x| x.attachment.filename.clone().into())
        .collect();

    // Remove any filter or delta files that are not listed in the collection
    for dir_entry in std::fs::read_dir(db_dir)? {
        let Ok(dir_entry) = dir_entry else { continue };
        let dir_entry_path = dir_entry.path();
        let extension = dir_entry_path
            .extension()
            .and_then(|os_str| os_str.to_str());
        if (extension == Some("delta") || extension == Some("filter"))
            && !expected_filenames.contains(&dir_entry.file_name())
        {
            info!("Removing {:?}", dir_entry.file_name());
            let _ = std::fs::remove_file(dir_entry_path);
        }
    }

    for filter in filters {
        let expected_digest = hex::decode(&filter.attachment.hash)
            .map_err(|_| CRLiteDBError::from("filter digest corrupted"))?;
        let path = db_dir.join(filter.attachment.filename.clone());
        if path.exists() {
            let digest = Sha256::digest(std::fs::read(&path)?);
            if expected_digest == digest.as_slice() {
                info!("Found existing copy of {}", filter.attachment.filename);
                continue;
            }
        }

        let filter_url = format!("{}{}", attachment_url, filter.attachment.location);
        info!(
            "Fetching {} from {}",
            filter.attachment.filename, filter_url
        );
        let filter_bytes = &reqwest::blocking::get(filter_url)
            .map_err(|_| CRLiteDBError::from("could not fetch filter"))?
            .bytes()
            .map_err(|_| CRLiteDBError::from("could not read filter"))?;

        let digest = Sha256::digest(filter_bytes);
        if expected_digest != digest.as_slice() {
            return Err(CRLiteDBError::from("filter digest mismatch"));
        }

        std::fs::write(&path, filter_bytes)?;
    }

    Ok(())
}

fn get_sct_ids_and_timestamps(cert: &X509Certificate) -> Vec<([u8; 32], u64)> {
    let sct_extension = match cert.tbs_certificate.get_extension_unique(OID_SCT_EXTENSION) {
        Ok(Some(sct_extension)) => sct_extension,
        _ => return vec![],
    };
    let scts = match sct_extension.parsed_extension() {
        ParsedExtension::SCT(scts) => scts,
        _ => return vec![],
    };
    scts.iter()
        .map(|sct| (*sct.id.key_id, sct.timestamp))
        .collect()
}

enum Filter {
    Clubcard(CRLiteClubcard),
}

impl Filter {
    fn from_bytes(bytes: &[u8]) -> Result<Self, CRLiteDBError> {
        if let Ok(clubcard) = CRLiteClubcard::from_bytes(bytes) {
            return Ok(Filter::Clubcard(clubcard));
        }
        Err(CRLiteDBError::from("could not load filter"))
    }

    fn has(
        &self,
        issuer_spki_hash: &[u8; 32],
        serial: &[u8],
        timestamps: &[([u8; 32], u64)],
    ) -> Status {
        match self {
            Filter::Clubcard(clubcard) => {
                let crlite_key = clubcard_crlite::CRLiteKey::new(issuer_spki_hash, serial);
                match clubcard.contains(&crlite_key, timestamps.iter().map(|(x, y)| (x, *y))) {
                    CRLiteStatus::Good => Status::Good,
                    CRLiteStatus::NotCovered => Status::NotCovered,
                    CRLiteStatus::NotEnrolled => Status::NotEnrolled,
                    CRLiteStatus::Revoked => Status::Revoked,
                }
            }
        }
    }
}

struct CRLiteDB {
    filters: Vec<Filter>,
    intermediates: Intermediates,
}

impl CRLiteDB {
    fn load(db_dir: &Path) -> Result<Self, CRLiteDBError> {
        let intermediates_path = db_dir.join("crlite.intermediates");

        let mut filters = vec![];
        for dir_entry in std::fs::read_dir(db_dir)? {
            let Ok(dir_entry) = dir_entry else { continue };
            let dir_entry_path = dir_entry.path();
            let extension = dir_entry_path
                .extension()
                .and_then(|os_str| os_str.to_str());
            if extension == Some("delta") || extension == Some("filter") {
                filters.push(Filter::from_bytes(&std::fs::read(dir_entry_path)?)?);
            }
        }

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
            filters,
            intermediates,
        })
    }

    pub fn query(&self, cert: &X509Certificate) -> Status {
        let serial = cert.tbs_certificate.raw_serial();

        debug!("Issuer DN: {}", cert.tbs_certificate.issuer);
        debug!("Serial number: {}", hex::encode(serial));

        let issuer_spki = match self.intermediates.lookup_issuer_spki(cert) {
            Some(issuer_spki) => issuer_spki.raw,
            _ => return Status::NotEnrolled,
        };

        let issuer_spki_hash: [u8; 32] = Sha256::digest(issuer_spki).into();

        debug!("Issuer SPKI hash: {}", URL_SAFE.encode(issuer_spki_hash));


        // An expired certificate, even if enrolled and covered, might
        // not be included in the filter.
        if !cert.tbs_certificate.validity.is_valid() {
            return Status::Expired;
        }

        let mut maybe_good = false;
        let mut covered = false;

        let issuer_spki_hash = Sha256::digest(issuer_spki);
        for filter in &self.filters {
            match filter.has(
                issuer_spki_hash.as_ref(),
                serial,
                &get_sct_ids_and_timestamps(cert),
            ) {
                Status::Revoked => return Status::Revoked,
                Status::Good => maybe_good = true,
                Status::NotEnrolled => covered = true,
                _ => (),
            }
        }
        if maybe_good {
            return Status::Good;
        }
        if covered {
            return Status::NotEnrolled;
        }
        Status::NotCovered
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
                    .or_default()
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
        if let Ok(result) = query_https_addr(db, host, addr, Arc::clone(&tls_config)) {
            return Ok(result);
        }
    }
    // None of the addresses for this host worked
    Err(CRLiteDBError::from(format!(
        "could not obtain cert for {}",
        host
    )))
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
        let input = match std::fs::read(file) {
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
    #[clap(long, value_enum, default_value = "default")]
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
    #[serde(rename = "experimental+deltas")]
    ExperimentalDeltas,
    #[default]
    Default,
    Compat,
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
        let (attachment_url, base_url) = match args.update.unwrap() {
            RemoteSettingsInstance::Dev => (STAGE_ATTACH_URL, STAGE_URL),
            RemoteSettingsInstance::Stage => (STAGE_ATTACH_URL, STAGE_URL),
            RemoteSettingsInstance::Prod => (PROD_ATTACH_URL, PROD_URL),
        };

        if let Err(e) = update_db(&args.db, attachment_url, base_url, &args.channel) {
            error!("{}", e.message);
            std::process::exit(1);
        }
    }

    let db = match CRLiteDB::load(&args.db) {
        Ok(db) => db,
        Err(e) => {
            error!("Error loading CRLite DB: {}", e.message);
            error!("Use --update [prod | stage] to populate DB.");
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
