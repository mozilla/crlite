//! # rust-create-cascade
//!
//! Builds a filter cascade from the output of crlite's `aggregate-known` and `aggregate-crls` programs.
//!
//! The aggregator program creates two directories `/known/` and `/revoked/` containing
//! issuer-specific files. Each file name is (the url-safe base64 encoding of) the SHA256 hash of
//! the DER encoded SubjectPublicKeyInfo field from the issuer's certificate. Each file contains
//! line delimited ascii hex encoded data. In the known directory, each line is a certificate
//! serial number. In the revoked directory, each line is a serial number prefixed by a one byte
//! revocation reason code.
//!
//! A filter cascade encodes a subset R of a set U.
//! Here we take U to be the set
//!    { IssuerSPKIHash || Serial : "IssuerSPKIHash, Serial in /known/" }.
//! and we take R to be the intersection of U with
//!    { IssuerSPKIHash || Serial : "IssuerSPKIHash, Serial in /revoked/" }.
//!
//! The IssuerSPKIHash and Serial values in these definitions are octet strings. We obtain
//! IssuerSPKIHash by applying `base64::decode_config(., base64::URL_SAFE)` to a file name. We
//! obtain Serial by applying `hex::decode(...)` to a line of a file.
//!
extern crate base64;
extern crate bincode;
extern crate clap;
extern crate hex;
extern crate log;
extern crate rand;
extern crate rayon;
extern crate rust_cascade;
extern crate statsd;
extern crate stderrlog;
extern crate tempfile;

use clap::Parser;
use log::*;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rust_cascade::{Cascade, CascadeBuilder, ExcludeSet, HashAlgorithm};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs::File;
use std::io::prelude::{BufRead, Write};
use std::io::{BufReader, Lines};
use std::path::{Path, PathBuf};
use std::time::Instant;

use rand::rngs::OsRng;
use rand::RngCore;

type Serial = String;

const REASON_UNSPECIFIED: u8 = 0;
const REASON_KEY_COMPROMISE: u8 = 1;
const REASON_CA_COMPROMISE: u8 = 2;
const REASON_AFFILIATION_CHANGED: u8 = 3;
const REASON_SUPERSEDED: u8 = 4;
const REASON_CESSATION_OF_OPERATION: u8 = 5;
const REASON_CERTIFICATE_HOLD: u8 = 6;
//              -- value 7 is not used
const REASON_REMOVE_FROM_CRL: u8 = 8;
const REASON_PRIVILEGE_WITHDRAWN: u8 = 9;
const REASON_AA_COMPROMISE: u8 = 10;

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
enum Reason {
    Unspecified = REASON_UNSPECIFIED,
    KeyCompromise = REASON_KEY_COMPROMISE,
    CACompromise = REASON_CA_COMPROMISE,
    AffilitationChanged = REASON_AFFILIATION_CHANGED,
    Superseded = REASON_SUPERSEDED,
    CessationOfOperation = REASON_CESSATION_OF_OPERATION,
    CertificateHold = REASON_CERTIFICATE_HOLD,
    RemoveFromCRL = REASON_REMOVE_FROM_CRL,
    PrivilegeWithdrawn = REASON_PRIVILEGE_WITHDRAWN,
    AACompromise = REASON_AA_COMPROMISE,
}

impl From<u8> for Reason {
    fn from(reason_code: u8) -> Reason {
        match reason_code {
            REASON_UNSPECIFIED => Reason::Unspecified,
            REASON_KEY_COMPROMISE => Reason::KeyCompromise,
            REASON_CA_COMPROMISE => Reason::CACompromise,
            REASON_AFFILIATION_CHANGED => Reason::AffilitationChanged,
            REASON_SUPERSEDED => Reason::Superseded,
            REASON_CESSATION_OF_OPERATION => Reason::CessationOfOperation,
            REASON_CERTIFICATE_HOLD => Reason::CertificateHold,
            REASON_REMOVE_FROM_CRL => Reason::RemoveFromCRL,
            REASON_PRIVILEGE_WITHDRAWN => Reason::PrivilegeWithdrawn,
            REASON_AA_COMPROMISE => Reason::AACompromise,
            _ => {
                warn!("Treating unrecognized reason code ({reason_code}) as unspecified");
                Reason::Unspecified
            }
        }
    }
}

fn decode_reason(hex_reason: &str) -> Reason {
    u8::from_str_radix(hex_reason, 16)
        .expect("invalid hex encoding")
        .into()
}

#[derive(Debug, Default)]
struct ReasonCodeHistogram {
    unspecified: usize, // "unused" in rfc5280
    key_compromise: usize,
    ca_compromise: usize,
    affiliation_changed: usize,
    superseded: usize,
    cessation_of_operation: usize,
    certificate_hold: usize,
    remove_from_crl: usize,
    privilege_withdrawn: usize,
    aa_compromise: usize,
}

impl ReasonCodeHistogram {
    fn add(&mut self, reason: Reason) {
        let bin = match reason {
            Reason::Unspecified => &mut self.unspecified,
            Reason::KeyCompromise => &mut self.key_compromise,
            Reason::CACompromise => &mut self.ca_compromise,
            Reason::AffilitationChanged => &mut self.affiliation_changed,
            Reason::Superseded => &mut self.superseded,
            Reason::CessationOfOperation => &mut self.cessation_of_operation,
            Reason::CertificateHold => &mut self.certificate_hold,
            Reason::RemoveFromCRL => &mut self.remove_from_crl,
            Reason::PrivilegeWithdrawn => &mut self.privilege_withdrawn,
            Reason::AACompromise => &mut self.aa_compromise,
        };
        *bin += 1;
    }

    fn merge(mut self, other: Self) -> Self {
        self.unspecified += other.unspecified;
        self.key_compromise += other.key_compromise;
        self.ca_compromise += other.ca_compromise;
        self.affiliation_changed += other.affiliation_changed;
        self.superseded += other.superseded;
        self.cessation_of_operation += other.cessation_of_operation;
        self.certificate_hold += other.certificate_hold;
        self.remove_from_crl += other.remove_from_crl;
        self.privilege_withdrawn += other.privilege_withdrawn;
        self.aa_compromise += other.aa_compromise;
        self
    }
}

#[derive(clap::ValueEnum, Copy, Clone)]
enum ReasonSet {
    All,
    Specified,
    Priority,
}

struct RevokedSerialAndReasonIterator {
    lines: Lines<BufReader<File>>,
    reason_set: ReasonSet,
}

impl RevokedSerialAndReasonIterator {
    fn new(path: &Path, reason_set: ReasonSet) -> Self {
        Self {
            lines: BufReader::new(File::open(path).unwrap()).lines(),
            reason_set,
        }
    }

    fn skip_reason(&self, reason: &Reason) -> bool {
        match self.reason_set {
            ReasonSet::All => false,
            ReasonSet::Specified => *reason == Reason::Unspecified,
            ReasonSet::Priority => {
                !matches!(*reason, Reason::KeyCompromise | Reason::CessationOfOperation | Reason::PrivilegeWithdrawn)
            },
        }
    }
}

impl Iterator for RevokedSerialAndReasonIterator {
    type Item = (Serial, Reason);
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(mut line) = self.lines.next().transpose().expect("IO error") {
            let reason = decode_reason(&line[..2]);
            if self.skip_reason(&reason) {
                continue;
            }
            let serial = line.split_off(2);
            return Some((serial, reason));
        }
        None
    }
}

impl From<RevokedSerialAndReasonIterator> for HashSet<Serial> {
    fn from(iter: RevokedSerialAndReasonIterator) -> HashSet<Serial> {
        iter.map(|(serial, _)| serial).collect()
    }
}

impl From<RevokedSerialAndReasonIterator> for HashMap<Serial, Reason> {
    fn from(iter: RevokedSerialAndReasonIterator) -> HashMap<Serial, Reason> {
        iter.collect()
    }
}

struct KnownSerialIterator {
    lines: Lines<BufReader<File>>,
}

impl KnownSerialIterator {
    fn new(path: &Path) -> Self {
        Self {
            lines: BufReader::new(File::open(path).unwrap()).lines(),
        }
    }
}

impl Iterator for KnownSerialIterator {
    type Item = String;
    fn next(&mut self) -> Option<Self::Item> {
        self.lines.next().transpose().expect("io error")
    }
}

fn decode_issuer(s: &str) -> Vec<u8> {
    base64::decode_config(s, base64::URL_SAFE)
        .expect("found invalid issuer id: not url-safe base64.")
}

fn decode_serial(s: &str) -> Vec<u8> {
    hex::decode(s.as_bytes()).expect("found invalid serial number: not ascii hex.")
}

/// `crlite_key` creates an element of U from (decoded) IssuerSPKIHash and Serial values.
///
/// # Arguments
/// * `issuer`: a sha256 hash of a DER encoded subject public key info.
/// * `serial`: a DER integer without the tag-length prefix.
fn crlite_key(issuer: &[u8], serial: &[u8]) -> Vec<u8> {
    let mut key = issuer.to_vec();
    key.extend_from_slice(serial);
    key
}

/// list_issuer_file_pairs pairs files in `known_dir` and `revoked_dir` by issuer.
/// It returns a list of tuples containing
///     - an IssuerSPKIHash,
///     - the path to that issuer's file in `revoked_dir` (or None)
///     - the path to that issuer's file in `known_dir`.
///
/// Note: Files in `revoked_dir` that do not have a partner in `known_dir` are ignored.
/// Such a file would list serial numbers that the aggregator did not see in any CT log.
fn list_issuer_file_pairs(
    revoked_dir: &Path,
    known_dir: &Path,
) -> Vec<(Vec<u8>, Option<PathBuf>, PathBuf)> {
    let known_files = Path::read_dir(known_dir).unwrap();
    let known_issuers: Vec<OsString> = known_files
        .filter_map(|x| x.ok())
        .map(|x| x.file_name())
        .collect();

    let mut pairs = vec![];
    for issuer in known_issuers {
        let k_file = known_dir.join(&issuer);
        let r_file = revoked_dir.join(&issuer);
        let issuer_bytes = decode_issuer(issuer.to_str().expect("non-unicode issuer string"));
        if r_file.exists() {
            pairs.push((issuer_bytes, Some(r_file), k_file));
        } else {
            pairs.push((issuer_bytes, None, k_file));
        }
    }

    pairs
}

/// `count` obtains an upper bound on the number of distinct serial numbers in `revoked_serials_and_reasons` and
/// `known_serials`.
///
/// The first return value is *exactly* the number of distinct serial numbers in `revoked_serials_and_reasons`
/// which appear in `known_serials`.
///
/// The second value is the number of serial numbers in `known_serials` *with multiplicity* that do
/// not appear in `revoked_serials_and_reasons`.
///
/// The reasoning here is that `known_serials` might be too large to fit in memory, so we're
/// willing to accept duplicates. Note that filter size is primarily determined by the number of
/// included elements, so duplicate excluded elements have little impact.
///
/// This function also returns the number of revoked serials broken out by reason code.
///
fn count(
    revoked_serials_and_reasons: Option<RevokedSerialAndReasonIterator>,
    known_serials: KnownSerialIterator,
) -> (usize, usize, ReasonCodeHistogram) {
    let mut ok_count: usize = 0;
    let mut known_revoked_serial_set = HashSet::new();
    let mut reasons = ReasonCodeHistogram::default();

    let revoked_serial_to_reason_map: HashMap<Serial, Reason> = revoked_serials_and_reasons
        .map(|iter| iter.into())
        .unwrap_or_default();

    for serial in known_serials {
        if let Some(reason) = revoked_serial_to_reason_map.get(serial.as_str()) {
            known_revoked_serial_set.insert(serial);
            reasons.add(*reason);
        } else {
            ok_count += 1;
        }
    }

    let revoked_count = known_revoked_serial_set.len();
    (revoked_count, ok_count, reasons)
}

/// `include` finds revoked serials that are known and includes them in the filter cascade.
fn include(
    builder: &mut CascadeBuilder,
    issuer: &[u8],
    revoked_serials_and_reasons: RevokedSerialAndReasonIterator,
    known_serials: KnownSerialIterator,
) {
    let mut revoked_serial_set: HashSet<Serial> = revoked_serials_and_reasons.into();

    for serial in known_serials {
        if revoked_serial_set.contains(&serial) {
            let key = crlite_key(issuer, &decode_serial(&serial));
            builder
                .include(key)
                .expect("Capacity error. Did the file contents change?");
            // Ensure that we do not attempt to include this issuer+serial again.
            revoked_serial_set.remove(&serial);
        }
    }
}

/// `exclude` finds known serials that are not revoked excludes them from the filter cascade.
/// It returns an `ExcludeSet` which must be emptied into the builder using
/// `CascadeBuilder::collect_exclude_set` before `CascadeBuilder::finalize` is called.
fn exclude(
    builder: &CascadeBuilder,
    issuer: &[u8],
    revoked_serials_and_reasons: Option<RevokedSerialAndReasonIterator>,
    known_serials: KnownSerialIterator,
) -> ExcludeSet {
    let mut exclude_set = ExcludeSet::default();
    let revoked_serial_set: HashSet<Serial> = revoked_serials_and_reasons
        .map(|iter| iter.into())
        .unwrap_or_default();

    let non_revoked_serials = known_serials.filter(|x| !revoked_serial_set.contains(x));
    for serial in non_revoked_serials {
        let key = crlite_key(issuer, &decode_serial(&serial));
        builder.exclude_threaded(&mut exclude_set, key);
    }
    exclude_set
}

/// `check` verifies that a cascade labels items correctly.
fn check(
    cascade: &Cascade,
    issuer: &[u8],
    revoked_serials_and_reasons: Option<RevokedSerialAndReasonIterator>,
    known_serials: KnownSerialIterator,
) {
    let revoked_serial_set: HashSet<Serial> = revoked_serials_and_reasons
        .map(|iter| iter.into())
        .unwrap_or_default();

    for serial in known_serials {
        assert_eq!(
            cascade.has(crlite_key(issuer, &decode_serial(&serial))),
            revoked_serial_set.contains(&serial)
        );
    }
}

/// `count_all` performs a parallel iteration over file pairs, applies
/// `count` to each pair, and sums up the results.
fn count_all(
    revoked_dir: &Path,
    known_dir: &Path,
    reason_set: ReasonSet,
) -> (usize, usize, ReasonCodeHistogram) {
    list_issuer_file_pairs(revoked_dir, known_dir)
        .par_iter()
        .map(|pair| {
            let (_, revoked_file, known_file) = pair;
            let revoked_serials_and_reasons = revoked_file
                .as_ref()
                .map(|x| RevokedSerialAndReasonIterator::new(x, reason_set));
            let known_serials = KnownSerialIterator::new(known_file);
            count(revoked_serials_and_reasons, known_serials)
        })
        .reduce(
            || (0, 0, ReasonCodeHistogram::default()),
            |a, b| (a.0 + b.0, a.1 + b.1, a.2.merge(b.2)),
        )
}

/// `check_all` performs a parallel iteration over file pairs, and applies
/// `check` to each pair.
fn check_all(cascade: &Cascade, revoked_dir: &Path, known_dir: &Path, reason_set: ReasonSet) {
    list_issuer_file_pairs(revoked_dir, known_dir)
        .par_iter()
        .for_each(|pair| {
            let (issuer, revoked_file, known_file) = pair;
            let revoked_serials_and_reasons = revoked_file
                .as_ref()
                .map(|x| RevokedSerialAndReasonIterator::new(x, reason_set));
            let known_serials = KnownSerialIterator::new(known_file);
            check(cascade, issuer, revoked_serials_and_reasons, known_serials);
        });
}

/// `include_all` performs a serial iteration over file pairs, and applies
/// `include` to each pair.
fn include_all(
    builder: &mut CascadeBuilder,
    revoked_dir: &Path,
    known_dir: &Path,
    reason_set: ReasonSet,
) {
    // Include file pairs with a revoked component. Must be done serially, as
    // CascadeBuilder::include takes &mut self.
    for pair in list_issuer_file_pairs(revoked_dir, known_dir).iter() {
        if let (issuer, Some(revoked_file), known_file) = pair {
            include(
                builder,
                issuer,
                RevokedSerialAndReasonIterator::new(revoked_file, reason_set),
                KnownSerialIterator::new(known_file),
            );
        }
    }
}

/// `exclude_all` performs a parallel iteration over file pairs, and applies
/// `exclude` to each pair and empties the returned `ExcludeSet`s into the builder.
fn exclude_all(
    builder: &mut CascadeBuilder,
    revoked_dir: &Path,
    known_dir: &Path,
    reason_set: ReasonSet,
) {
    let mut exclude_sets: Vec<ExcludeSet> = list_issuer_file_pairs(revoked_dir, known_dir)
        .par_iter()
        .map(|pair| {
            let (issuer, revoked_file, known_file) = pair;
            let revoked_serials_and_reasons = revoked_file
                .as_ref()
                .map(|x| RevokedSerialAndReasonIterator::new(x, reason_set));
            let known_serials = KnownSerialIterator::new(known_file);
            exclude(builder, issuer, revoked_serials_and_reasons, known_serials)
        })
        .collect();

    exclude_sets
        .iter_mut()
        .for_each(|x| builder.collect_exclude_set(x).unwrap());
}

/// `create_cascade` runs through the full filter generation process and writes a cascade to
/// `out_file`.
fn create_cascade(
    out_file: &Path,
    revoked_dir: &Path,
    known_dir: &Path,
    hash_alg: HashAlgorithm,
    reason_set: ReasonSet,
    statsd_client: Option<&statsd::Client>,
) {
    info!("Counting serials");
    let (revoked, not_revoked, reasons) = count_all(revoked_dir, known_dir, reason_set);

    info!(
        "Found {} 'revoked' and {} 'not revoked' serial numbers",
        revoked, not_revoked
    );
    info!("Revocation reason codes: {:?}", reasons);

    let salt_len = match hash_alg {
        HashAlgorithm::MurmurHash3 => 0,
        HashAlgorithm::Sha256l32 => 16,
        HashAlgorithm::Sha256 => 16,
    };

    let mut salt = vec![0u8; salt_len];
    if salt_len > 0 {
        OsRng.fill_bytes(&mut salt);
    }

    let mut builder = CascadeBuilder::new(hash_alg, salt, revoked, not_revoked);

    info!("Processing revoked serials");
    include_all(&mut builder, revoked_dir, known_dir, reason_set);

    info!("Processing non-revoked serials");
    exclude_all(&mut builder, revoked_dir, known_dir, reason_set);

    info!("Eliminating false positives");
    let cascade = builder.finalize().expect("build error");

    info!("Testing serialization");
    let cascade_bytes = cascade.to_bytes().expect("cannot serialize cascade");
    info!("Cascade is {} bytes", cascade_bytes.len());

    if let Some(cascade) =
        Cascade::from_bytes(cascade_bytes.clone()).expect("cannot deserialize cascade")
    {
        info!("\n{}", cascade);

        info!("Verifying cascade");
        check_all(&cascade, revoked_dir, known_dir, reason_set);
    } else {
        warn!("Produced empty cascade. Exiting.");
        return;
    }

    info!("Writing cascade to {}", out_file.display());
    let mut filter_writer = File::create(out_file).expect("cannot open file");
    filter_writer
        .write_all(&cascade_bytes)
        .expect("can't write file");

    if let Some(client) = statsd_client {
        client.gauge("filter_size", cascade_bytes.len() as f64);
        client.gauge("not_revoked", not_revoked as f64);
        client.gauge("revoked", revoked as f64);
        client.gauge("revoked.unspecified", reasons.unspecified as f64);
        client.gauge("revoked.key_compromise", reasons.key_compromise as f64);
        client.gauge("revoked.ca_compromise", reasons.ca_compromise as f64);
        client.gauge(
            "revoked.affiliation_changed",
            reasons.affiliation_changed as f64,
        );
        client.gauge("revoked.superseded", reasons.superseded as f64);
        client.gauge(
            "revoked.cessation_of_operation",
            reasons.cessation_of_operation as f64,
        );
        client.gauge("revoked.certificate_hold", reasons.certificate_hold as f64);
        client.gauge("revoked.remove_from_crl", reasons.remove_from_crl as f64);
        client.gauge(
            "revoked.privilege_withdrawn",
            reasons.privilege_withdrawn as f64,
        );
        client.gauge("revoked.aa_compromise", reasons.aa_compromise as f64);
    }
}

/// `write_revset_and_stash` writes a revset and a stash to disk.
///
/// A revset is a representation of the set R (CRLite keys corresponding to known-revoked certificates).
/// A stash file represents the delta between revsets from different runs.
///
/// Revsets are only consumed by this program. Their format is subject to change (we currently
/// bincode a HashSet of CRLite keys).
///
/// Stashes are consumed by other programs. We use a custom serialization, which has the following
/// pseudo-grammar:
///
///     STASH := (ENTRY)*
///     ENTRY := (
///         serial_count: little endian u32,
///         issuer_len: u8,
///         issuer: [u8, issuer_len],
///         serials: [SERIAL; serial_count]
///     )
///     SERIAL := (len: u8, serial: [u8; len])
///
/// # Arguments
/// * revset_file: where to write the revset.
/// * stash_file: where to write the stash.
/// * prev_revset_file: where to find a revset produced by a previous run of this program.
/// * revoked_dir: the directory where lists of revoked serials can be found.
/// * known_dir: the directory where lists of known serials can be found.
///
fn write_revset_and_stash(
    revset_file: &Path,
    stash_file: &Path,
    prev_revset_file: &Path,
    revoked_dir: &Path,
    known_dir: &Path,
    reason_set: ReasonSet,
    statsd_client: Option<&statsd::Client>,
) {
    let mut prev_keys: HashSet<Vec<u8>> = HashSet::new();
    if prev_revset_file.exists() {
        let prev_list_bytes = std::fs::read(prev_revset_file).unwrap();
        if let Ok(decoded) = bincode::deserialize(&prev_list_bytes) {
            prev_keys = decoded;
        }
    } else {
        warn!("Previous revset not found. Stash file will be large.");
    }

    let mut revset: HashSet<Vec<u8>> = HashSet::new();
    let mut stash_bytes = vec![];

    for pair in list_issuer_file_pairs(revoked_dir, known_dir).iter() {
        if let (issuer, Some(revoked_file), known_file) = pair {
            let mut additions = vec![];
            let revoked_serial_set: HashSet<Serial> =
                RevokedSerialAndReasonIterator::new(revoked_file, reason_set).into();
            let known_revoked_serials =
                KnownSerialIterator::new(known_file).filter(|x| revoked_serial_set.contains(x));
            for serial in known_revoked_serials {
                let serial_bytes = decode_serial(&serial);
                let key = crlite_key(issuer, &serial_bytes);
                if !prev_keys.contains(&key) {
                    additions.push(serial_bytes);
                }
                revset.insert(key);
            }

            if !additions.is_empty() {
                stash_bytes.extend((additions.len() as u32).to_le_bytes());
                stash_bytes.push(issuer.len() as u8);
                stash_bytes.extend_from_slice(issuer);
                for serial in additions {
                    stash_bytes.push(serial.len() as u8);
                    stash_bytes.extend_from_slice(serial.as_ref());
                }
            }
        }
    }

    let revset_bytes = bincode::serialize(&revset).unwrap();
    info!("Revset is {} bytes", revset_bytes.len());
    let mut revset_writer = File::create(revset_file).expect("cannot open list file");
    revset_writer
        .write_all(&revset_bytes)
        .expect("can't write revset file");

    info!("Stash is {} bytes", stash_bytes.len());
    let mut stash_writer = File::create(stash_file).expect("cannot open stash file");
    stash_writer
        .write_all(&stash_bytes)
        .expect("can't write stash file");

    if let Some(client) = statsd_client {
        client.gauge("revset_size", revset_bytes.len() as f64);
        client.gauge("stash_size", stash_bytes.len() as f64);
    }
}

#[derive(Parser)]
struct Cli {
    #[clap(long, parse(from_os_str), default_value = "./known/")]
    known: PathBuf,
    #[clap(long, parse(from_os_str), default_value = "./revoked/")]
    revoked: PathBuf,
    #[clap(long, parse(from_os_str), default_value = "./prev_revset.bin")]
    prev_revset: PathBuf,
    #[clap(long, parse(from_os_str), default_value = ".")]
    outdir: PathBuf,
    #[clap(long, value_enum, default_value = "all")]
    reason_set: ReasonSet,
    #[clap(long)]
    statsd_host: Option<String>,
    #[clap(long)]
    murmurhash3: bool,
    #[clap(long)]
    clobber: bool,
    #[clap(short = 'v', parse(from_occurrences))]
    verbose: usize,
}

fn main() {
    let mut err = false;

    let args = Cli::parse();

    stderrlog::new()
        .module(module_path!())
        .verbosity(args.verbose)
        .init()
        .unwrap();

    let known_dir = &args.known;
    let revoked_dir = &args.revoked;
    let prev_revset_file = &args.prev_revset;
    let reason_set = args.reason_set;

    let out_dir = &args.outdir;
    let filter_file = &out_dir.join("filter");
    let stash_file = &out_dir.join("filter.stash");
    let revset_file = &out_dir.join("revset.bin");

    if !known_dir.exists() {
        error!("{} not found", known_dir.display());
        err = true;
    }
    if !revoked_dir.exists() {
        error!("{} not found", revoked_dir.display());
        err = true;
    }

    if std::fs::create_dir_all(out_dir).is_err() {
        error!("Could not create out directory: {}", out_dir.display());
        err = true;
    } else if !args.clobber {
        if filter_file.exists() {
            error!(
                "{} exists! Will not overwrite without --clobber.",
                filter_file.display()
            );
            err = true;
        }
        if stash_file.exists() {
            error!(
                "{} exists! Will not overwrite without --clobber.",
                stash_file.display()
            );
            err = true;
        }
        if revset_file.exists() {
            error!(
                "{} exists! Will not overwrite without --clobber.",
                revset_file.display()
            );
            err = true;
        }
    }
    if err {
        return;
    }

    let hash_alg = match args.murmurhash3 {
        true => HashAlgorithm::MurmurHash3,
        false => HashAlgorithm::Sha256,
    };

    let statsd_prefix = match reason_set {
        ReasonSet::All => "crlite.generate",
        ReasonSet::Specified => "crlite.generate.specified_reasons",
        ReasonSet::Priority => "crlite.generate.priority_reasons",
    };

    let statsd_client = match args.statsd_host {
        Some(ref statsd_host) if statsd_host.contains(':') => {
            // host specified with port
            statsd::Client::new(statsd_host, statsd_prefix).ok()
        }
        Some(ref statsd_host) => {
            // use default port
            statsd::Client::new(format!("{}:{}", statsd_host, 8125), statsd_prefix).ok()
        }
        None => None,
    };

    if args.statsd_host.is_some() && statsd_client.is_none() {
        info!("Could not connect to statsd {}", args.statsd_host.unwrap());
    }

    info!("Generating cascade");
    let timer_start = Instant::now();
    create_cascade(
        filter_file,
        revoked_dir,
        known_dir,
        hash_alg,
        reason_set,
        statsd_client.as_ref(),
    );

    info!("Generating stash file");
    write_revset_and_stash(
        revset_file,
        stash_file,
        prev_revset_file,
        revoked_dir,
        known_dir,
        reason_set,
        statsd_client.as_ref(),
    );
    let timer_finish = Instant::now() - timer_start;
    info!("Finished in {} seconds", timer_finish.as_secs());
    if let Some(client) = statsd_client {
        client.gauge("time", timer_finish.as_secs() as f64);
    }

    info!("Done");
}

#[cfg(test)]
mod tests {
    use super::{
        check_all, count_all, create_cascade, crlite_key, decode_issuer, decode_serial,
        write_revset_and_stash, Reason, ReasonSet,
    };
    use rand::rngs::OsRng;
    use rand::RngCore;
    use rust_cascade::{Cascade, HashAlgorithm};
    use std::collections::HashSet;
    use std::convert::TryInto;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::{tempdir, TempDir};

    struct TestEnv {
        dir: TempDir,
    }
    impl TestEnv {
        fn new() -> Self {
            let dir = tempdir().expect("could not create temp dir");
            std::fs::create_dir(dir.path().join("known")).expect("could not create known dir");
            std::fs::create_dir(dir.path().join("revoked")).expect("could not create revoked dir");
            Self { dir }
        }

        fn known_dir(&self) -> PathBuf {
            self.dir.path().join("known")
        }

        fn revoked_dir(&self) -> PathBuf {
            self.dir.path().join("revoked")
        }

        fn add_issuer(&self) -> String {
            let mut issuer_bytes = vec![0u8; 32];
            OsRng.fill_bytes(&mut issuer_bytes);

            let issuer_str = base64::encode_config(issuer_bytes, base64::URL_SAFE);
            std::fs::File::create(self.known_dir().join(&issuer_str))
                .expect("could not create issuer file");
            std::fs::File::create(self.revoked_dir().join(&issuer_str))
                .expect("could not create issuer file");
            issuer_str
        }

        fn add_serial(&self, issuer: &str) -> String {
            let mut serial_bytes = vec![0u8; 20];
            OsRng.fill_bytes(&mut serial_bytes);

            let mut known_file = std::fs::OpenOptions::new()
                .write(true)
                .append(true)
                .open(self.known_dir().join(issuer))
                .expect("could not open known file");

            let serial_str = hex::encode(serial_bytes);
            writeln!(known_file, "{}", serial_str).expect("write failed");

            serial_str
        }

        fn add_revoked_serial(&self, issuer: &str, reason: Reason) -> String {
            let mut serial_bytes = vec![0u8; 20];
            OsRng.fill_bytes(&mut serial_bytes);

            let mut known_file = std::fs::OpenOptions::new()
                .write(true)
                .append(true)
                .open(self.known_dir().join(issuer))
                .expect("could not open known file");

            let mut revoked_file = std::fs::OpenOptions::new()
                .write(true)
                .append(true)
                .open(self.revoked_dir().join(issuer))
                .expect("could not open revoked file");

            let serial_str = hex::encode(serial_bytes);
            let reason_str = hex::encode(&[reason as u8]);
            writeln!(known_file, "{}", serial_str).expect("write failed");
            writeln!(revoked_file, "{}{}", reason_str, serial_str).expect("write failed");

            serial_str
        }
    }

    #[test]
    fn test_count_all() {
        let env = TestEnv::new();
        let issuer = env.add_issuer();
        for _ in 1..=86 {
            env.add_serial(&issuer);
        }
        for _ in 1..=75 {
            env.add_revoked_serial(&issuer, Reason::Unspecified);
        }
        for _ in 1..=30 {
            env.add_revoked_serial(&issuer, Reason::KeyCompromise);
        }
        for _ in 1..=9 {
            env.add_revoked_serial(&issuer, Reason::PrivilegeWithdrawn);
        }

        let (revoked, known, dist) =
            count_all(&env.revoked_dir(), &env.known_dir(), ReasonSet::All);
        assert_eq!(known, 86);
        assert_eq!(revoked, 75 + 30 + 9);
        assert_eq!(dist.unspecified, 75);
        assert_eq!(dist.key_compromise, 30);
        assert_eq!(dist.ca_compromise, 0);
        assert_eq!(dist.affiliation_changed, 0);
        assert_eq!(dist.superseded, 0);
        assert_eq!(dist.cessation_of_operation, 0);
        assert_eq!(dist.certificate_hold, 0);
        assert_eq!(dist.remove_from_crl, 0);
        assert_eq!(dist.privilege_withdrawn, 9);
        assert_eq!(dist.aa_compromise, 0);

        let (revoked, known, dist) =
            count_all(&env.revoked_dir(), &env.known_dir(), ReasonSet::Specified);
        assert_eq!(known, 86 + 75);
        assert_eq!(revoked, 30 + 9);
        assert_eq!(dist.unspecified, 0);
        assert_eq!(dist.key_compromise, 30);
        assert_eq!(dist.ca_compromise, 0);
        assert_eq!(dist.affiliation_changed, 0);
        assert_eq!(dist.superseded, 0);
        assert_eq!(dist.cessation_of_operation, 0);
        assert_eq!(dist.certificate_hold, 0);
        assert_eq!(dist.remove_from_crl, 0);
        assert_eq!(dist.privilege_withdrawn, 9);
        assert_eq!(dist.aa_compromise, 0);

        let (revoked, known, dist) = count_all(
            &env.revoked_dir(),
            &env.known_dir(),
            ReasonSet::Priority,
        );
        assert_eq!(known, 86 + 75);
        assert_eq!(revoked, 30 + 9);
        assert_eq!(dist.unspecified, 0);
        assert_eq!(dist.key_compromise, 30);
        assert_eq!(dist.ca_compromise, 0);
        assert_eq!(dist.affiliation_changed, 0);
        assert_eq!(dist.superseded, 0);
        assert_eq!(dist.cessation_of_operation, 0);
        assert_eq!(dist.certificate_hold, 0);
        assert_eq!(dist.remove_from_crl, 0);
        assert_eq!(dist.privilege_withdrawn, 9);
        assert_eq!(dist.aa_compromise, 0);
    }

    #[test]
    fn test_revset_and_stash() {
        let env = TestEnv::new();

        let issuer = env.add_issuer();
        for _ in 1..=1000 {
            env.add_serial(&issuer);
        }
        env.add_revoked_serial(&issuer, Reason::KeyCompromise);

        let filter_file = env.dir.path().join("filter");
        let stash_file = env.dir.path().join("filter.stash");
        let revset_file = env.dir.path().join("revset.bin");
        let prev_revset_file = env.dir.path().join("old-revset.bin");

        create_cascade(
            &filter_file,
            &env.revoked_dir(),
            &env.known_dir(),
            HashAlgorithm::Sha256,
            ReasonSet::All,
            None,
        );

        write_revset_and_stash(
            &revset_file,
            &stash_file,
            &prev_revset_file,
            &env.revoked_dir(),
            &env.known_dir(),
            ReasonSet::All,
            None,
        );

        std::fs::rename(&revset_file, &prev_revset_file).expect("could not move revset file");
        let first_revset_bytes = std::fs::read(&prev_revset_file).expect("could not read revset");
        let first_revset: HashSet<Vec<u8>> =
            bincode::deserialize(&first_revset_bytes).expect("could not parse revset");

        // Add a revoked serial after writing the first revset and stash
        let serial = env.add_revoked_serial(&issuer, Reason::Unspecified);

        write_revset_and_stash(
            &revset_file,
            &stash_file,
            &prev_revset_file,
            &env.revoked_dir(),
            &env.known_dir(),
            ReasonSet::All,
            None,
        );

        let second_revset_bytes = std::fs::read(&revset_file).expect("could not read revset");
        let second_revset: HashSet<Vec<u8>> =
            bincode::deserialize(&second_revset_bytes).expect("could not parse revset");

        let serial_bytes = decode_serial(&serial);
        let issuer_bytes = decode_issuer(&issuer);
        let key = crlite_key(&issuer_bytes, &serial_bytes);

        // The newly revoked serial should be in the second revset
        assert!(!first_revset.contains(&key));
        assert!(second_revset.contains(&key));

        // The stash should contain the newly revoked serial.
        let stash = std::fs::read(&stash_file).expect("could not read stash file");
        assert_eq!(u32::from_le_bytes(stash[0..4].try_into().unwrap()), 1);
        assert_eq!(stash[4] as usize, issuer_bytes.len());
        assert_eq!(stash[5..5 + issuer_bytes.len()], issuer_bytes);
        assert_eq!(stash[5 + issuer_bytes.len()] as usize, serial_bytes.len());
        assert_eq!(stash[5 + issuer_bytes.len() + 1..], serial_bytes);

        // Write the revset again using ReasonSet::Specified, so the newly revoked serial
        // will not be treated as revoked.
        write_revset_and_stash(
            &revset_file,
            &stash_file,
            &prev_revset_file,
            &env.revoked_dir(),
            &env.known_dir(),
            ReasonSet::Specified,
            None,
        );

        let third_revset_bytes = std::fs::read(&revset_file).expect("could not read revset");
        let third_revset: HashSet<Vec<u8>> =
            bincode::deserialize(&third_revset_bytes).expect("could not parse revset");

        // The newly revoked serial should not be in the third revset as it has
        // an unspecified reason code
        assert!(!third_revset.contains(&key));

        // The stash should be empty
        let stash = std::fs::read(&stash_file).expect("could not read stash file");
        assert_eq!(stash.len(), 0);
    }

    #[test]
    #[should_panic]
    fn test_check_all_with_wrong_reason_set() {
        let env = TestEnv::new();

        let issuer = env.add_issuer();
        env.add_serial(&issuer);
        env.add_revoked_serial(&issuer, Reason::KeyCompromise);
        env.add_revoked_serial(&issuer, Reason::Unspecified);

        let filter_file = env.dir.path().join("filter");

        // Use ReasonSet::Specified while creating the filter
        create_cascade(
            &filter_file,
            &env.revoked_dir(),
            &env.known_dir(),
            HashAlgorithm::Sha256,
            ReasonSet::Specified,
            None,
        );

        let filter_bytes = std::fs::read(&filter_file).expect("could not read filter file");
        let cascade = Cascade::from_bytes(filter_bytes)
            .expect("cannot deserialize cascade")
            .expect("cascade should be some");

        // Checking with ReasonSet::All will panic
        check_all(
            &cascade,
            &env.revoked_dir(),
            &env.known_dir(),
            ReasonSet::All,
        );
    }
}
