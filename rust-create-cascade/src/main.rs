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

use clap::Parser;
use log::*;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rust_cascade::{Cascade, CascadeBuilder, ExcludeSet, HashAlgorithm};
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::prelude::{BufRead, Write};
use std::io::{BufReader, Lines};
use std::path::{Path, PathBuf};
use std::time::Instant;

use rand::rngs::OsRng;
use rand::RngCore;

#[derive(Debug, Default)]
struct ReasonCodeHistogram {
    unspecified: usize, // "unused" in rfc5280
    key_compromise: usize,
    ca_compromise: usize,
    affiliation_changed: usize,
    superseded: usize,
    cessation_of_operation: usize,
    certificate_hold: usize,
    privilege_withdrawn: usize,
    aa_compromise: usize,
}

impl ReasonCodeHistogram {
    fn add(&mut self, reason: u8) {
        let bin = match reason {
            1 => &mut self.key_compromise,
            2 => &mut self.ca_compromise,
            3 => &mut self.affiliation_changed,
            4 => &mut self.superseded,
            5 => &mut self.cessation_of_operation,
            6 => &mut self.certificate_hold,
            7 => &mut self.privilege_withdrawn,
            8 => &mut self.aa_compromise,
            _ => &mut self.unspecified,
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
        self.privilege_withdrawn += other.privilege_withdrawn;
        self.aa_compromise += other.aa_compromise;
        self
    }
}

fn read_file_by_lines(path: &Path) -> Lines<BufReader<File>> {
    BufReader::new(File::open(path).unwrap()).lines()
}

fn decode_issuer(s: &OsStr) -> Vec<u8> {
    let issuer_str = s.to_str().expect("found invalid file name: not unicode.");
    base64::decode_config(issuer_str, base64::URL_SAFE)
        .expect("found invalid file name: not url-safe base64.")
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
        let issuer_bytes = decode_issuer(&issuer);
        if r_file.exists() {
            pairs.push((issuer_bytes, Some(r_file), k_file));
        } else {
            pairs.push((issuer_bytes, None, k_file));
        }
    }

    pairs
}

/// `count` obtains an upper bound on the number of distinct serial numbers in `revoked_serials` and
/// `known_serials`.
///
/// The first return value is *exactly* the number of distinct serial numbers in `revoked_serials`
/// which appear in `known_serials`.
///
/// The second value is the number of serial numbers in `known_serials` *with multiplicity* that do
/// not appear in `revoked_serials`.
///
/// The reasoning here is that `known_serials` might be too large to fit in memory, so we're
/// willing to accept duplicates. Note that filter size is primarily determined by the number of
/// included elements, so duplicate excluded elements have little impact.
///
/// This function also returns the number of revoked serials broken out by reason code.
///
fn count<T>(
    revoked_serials: Option<Lines<T>>,
    known_serials: &mut Lines<T>,
) -> (usize, usize, ReasonCodeHistogram)
where
    T: std::io::BufRead,
{
    let mut ok_count: usize = 0;
    let mut revoked_serial_set = HashMap::new();
    let mut known_revoked_serial_set = HashSet::new();
    let mut reasons = ReasonCodeHistogram::default();

    if let Some(mut revoked_serials) = revoked_serials {
        while let Some(Ok(mut line)) = revoked_serials.next() {
            let reason = u8::from_str_radix(&line[..2], 16).expect("invalid hex encoding");
            revoked_serial_set.insert(line.split_off(2), reason);
        }
    }

    while let Some(Ok(serial)) = known_serials.next() {
        if let Some(reason) = revoked_serial_set.get(serial.as_str()) {
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
fn include<T>(
    builder: &mut CascadeBuilder,
    issuer: &[u8],
    revoked_serials: &mut Lines<T>,
    known_serials: &mut Lines<T>,
) where
    T: std::io::BufRead,
{
    let mut revoked_serial_set = HashSet::new();

    while let Some(Ok(mut line)) = revoked_serials.next() {
        revoked_serial_set.insert(line.split_off(2));
    }

    while let Some(Ok(ref serial)) = known_serials.next() {
        if revoked_serial_set.contains(serial) {
            let key = crlite_key(issuer, &decode_serial(serial));
            builder
                .include(key)
                .expect("Capacity error. Did the file contents change?");
            // Ensure that we do not attempt to include this issuer+serial again.
            revoked_serial_set.remove(serial);
        }
    }
}

/// `exclude` finds known serials that are not revoked excludes them from the filter cascade.
/// It returns an `ExcludeSet` which must be emptied into the builder using
/// `CascadeBuilder::collect_exclude_set` before `CascadeBuilder::finalize` is called.
fn exclude<T>(
    builder: &CascadeBuilder,
    issuer: &[u8],
    revoked_serials: Option<Lines<T>>,
    known_serials: &mut Lines<T>,
) -> ExcludeSet
where
    T: std::io::BufRead,
{
    let mut exclude_set = ExcludeSet::default();
    let mut revoked_serial_set = HashSet::new();

    if let Some(mut revoked_serials) = revoked_serials {
        while let Some(Ok(mut line)) = revoked_serials.next() {
            revoked_serial_set.insert(line.split_off(2));
        }
    }

    while let Some(Ok(ref serial)) = known_serials.next() {
        if !revoked_serial_set.contains(serial) {
            let key = crlite_key(issuer, &decode_serial(serial));
            builder.exclude_threaded(&mut exclude_set, key);
        }
    }
    exclude_set
}

/// `check` verifies that a cascade labels items correctly.
fn check<T>(
    cascade: &Cascade,
    issuer: &[u8],
    revoked_serials: Option<Lines<T>>,
    known_serials: &mut Lines<T>,
) where
    T: std::io::BufRead,
{
    let mut revoked_serial_set = HashSet::new();

    if let Some(mut revoked_serials) = revoked_serials {
        while let Some(Ok(mut line)) = revoked_serials.next() {
            revoked_serial_set.insert(line.split_off(2));
        }
    }

    while let Some(Ok(ref serial)) = known_serials.next() {
        assert_eq!(
            cascade.has(crlite_key(issuer, &decode_serial(serial))),
            revoked_serial_set.contains(serial)
        );
    }
}

/// `count_all` performs a parallel iteration over file pairs, applies
/// `count` to each pair, and sums up the results.
fn count_all(revoked_dir: &Path, known_dir: &Path) -> (usize, usize, ReasonCodeHistogram) {
    list_issuer_file_pairs(revoked_dir, known_dir)
        .par_iter()
        .map(|pair| {
            let (_, revoked_file, known_file) = pair;
            let revoked_serials = revoked_file.as_ref().map(|x| read_file_by_lines(x));
            let mut known_serials = read_file_by_lines(known_file);
            count(revoked_serials, &mut known_serials)
        })
        .reduce(
            || (0, 0, ReasonCodeHistogram::default()),
            |a, b| (a.0 + b.0, a.1 + b.1, a.2.merge(b.2)),
        )
}

/// `check_all` performs a parallel iteration over file pairs, and applies
/// `check` to each pair.
fn check_all(cascade: &Cascade, revoked_dir: &Path, known_dir: &Path) {
    list_issuer_file_pairs(revoked_dir, known_dir)
        .par_iter()
        .for_each(|pair| {
            let (issuer, revoked_file, known_file) = pair;
            let revoked_serials = revoked_file.as_ref().map(|x| read_file_by_lines(x));
            let mut known_serials = read_file_by_lines(known_file);
            check(cascade, issuer, revoked_serials, &mut known_serials);
        });
}

/// `include_all` performs a serial iteration over file pairs, and applies
/// `include` to each pair.
fn include_all(builder: &mut CascadeBuilder, revoked_dir: &Path, known_dir: &Path) {
    // Include file pairs with a revoked component. Must be done serially, as
    // CascadeBuilder::include takes &mut self.
    for pair in list_issuer_file_pairs(revoked_dir, known_dir).iter() {
        if let (issuer, Some(revoked_file), known_file) = pair {
            include(
                builder,
                issuer,
                &mut read_file_by_lines(revoked_file),
                &mut read_file_by_lines(known_file),
            );
        }
    }
}

/// `exclude_all` performs a parallel iteration over file pairs, and applies
/// `exclude` to each pair and empties the returned `ExcludeSet`s into the builder.
fn exclude_all(builder: &mut CascadeBuilder, revoked_dir: &Path, known_dir: &Path) {
    let mut exclude_sets: Vec<ExcludeSet> = list_issuer_file_pairs(revoked_dir, known_dir)
        .par_iter()
        .map(|pair| {
            let (issuer, revoked_file, known_file) = pair;
            let revoked_serials = revoked_file.as_ref().map(|x| read_file_by_lines(x));
            let mut known_serials = read_file_by_lines(known_file);
            exclude(builder, issuer, revoked_serials, &mut known_serials)
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
    statsd_client: Option<&statsd::Client>,
) {
    info!("Counting serials");
    let (revoked, not_revoked, reasons) = count_all(revoked_dir, known_dir);

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
    include_all(&mut builder, revoked_dir, known_dir);

    info!("Processing non-revoked serials");
    exclude_all(&mut builder, revoked_dir, known_dir);

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
        check_all(&cascade, revoked_dir, known_dir);
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
        client.gauge("generate.filter_size", cascade_bytes.len() as f64);
        client.gauge("generate.not_revoked", not_revoked as f64);
        client.gauge("generate.revoked", revoked as f64);
        client.gauge("generate.revoked.unspecified", reasons.unspecified as f64);
        client.gauge(
            "generate.revoked.key_compromise",
            reasons.key_compromise as f64,
        );
        client.gauge(
            "generate.revoked.ca_compromise",
            reasons.ca_compromise as f64,
        );
        client.gauge(
            "generate.revoked.affiliation_changed",
            reasons.affiliation_changed as f64,
        );
        client.gauge("generate.revoked.superseded", reasons.superseded as f64);
        client.gauge(
            "generate.revoked.cessation_of_operation",
            reasons.cessation_of_operation as f64,
        );
        client.gauge(
            "generate.revoked.certificate_hold",
            reasons.certificate_hold as f64,
        );
        client.gauge(
            "generate.revoked.privilege_withdrawn",
            reasons.privilege_withdrawn as f64,
        );
        client.gauge(
            "generate.revoked.aa_compromise",
            reasons.aa_compromise as f64,
        );
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

    let mut revset = HashSet::new();
    let mut stash_bytes = vec![];

    for pair in list_issuer_file_pairs(revoked_dir, known_dir).iter() {
        if let (issuer, Some(revoked_file), known_file) = pair {
            let mut revoked_serial_set = HashSet::new();
            let mut additions = vec![];

            let mut revoked_serials = read_file_by_lines(revoked_file);
            while let Some(Ok(mut line)) = revoked_serials.next() {
                revoked_serial_set.insert(line.split_off(2));
            }

            let mut known_serials = read_file_by_lines(known_file);
            while let Some(Ok(ref serial)) = known_serials.next() {
                if revoked_serial_set.contains(serial) {
                    let serial_bytes = decode_serial(serial);
                    let key = crlite_key(issuer, &serial_bytes);
                    if !prev_keys.contains(&key) {
                        additions.push(serial_bytes);
                    }
                    revset.insert(key);
                }
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
        client.gauge("generate.revset_size", revset_bytes.len() as f64);
        client.gauge("generate.stash_size", stash_bytes.len() as f64);
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

    let statsd_client = match args.statsd_host {
        Some(ref statsd_host) if statsd_host.contains(':') => {
            // host specified with port
            statsd::Client::new(statsd_host, "crlite").ok()
        }
        Some(ref statsd_host) => {
            // use default port
            statsd::Client::new(format!("{}:{}", statsd_host, 8125), "crlite").ok()
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
        statsd_client.as_ref(),
    );

    info!("Generating stash file");
    write_revset_and_stash(
        revset_file,
        stash_file,
        prev_revset_file,
        revoked_dir,
        known_dir,
        statsd_client.as_ref(),
    );
    let timer_finish = Instant::now() - timer_start;
    info!("Finished in {} seconds", timer_finish.as_secs());
    if let Some(client) = statsd_client {
        client.gauge("generate.time", timer_finish.as_secs() as f64);
    }

    info!("Done");
}
