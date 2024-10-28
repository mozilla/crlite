/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! # rust-create-cascade
//!
//! Builds a filter cascade from the output of crlite's `aggregate-known` and `aggregate-crls` programs.
//!
//! The aggregator program creates two directories `/known/` and `/revoked/` containing
//! issuer-specific files. Each file name is (the url-safe base64 encoding of) the SHA256 hash of
//! the DER encoded SubjectPublicKeyInfo field from the issuer's certificate. Each file contains
//! newline delimited data.
//! In the known directory, each line is either
//!     1) an ascii hex encoded 64 bit unix timestamp prefixed by "@", or
//!     2) an ascii hex encoded certificate serial number.
//! The timestamps are truncated to the hour (or day depending on how the CRLite backend is
//! configured). The certificates that follow a timestamp share the same (truncated) notAfter
//! date.
//! In the revoked directory, each line is an ascii hex encoded serial number prefixed by an ascii
//! hex encoded revocation reason code. The reason codes are one byte.
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
extern crate clubcard;
extern crate clubcard_crlite;
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
use rust_cascade::HashAlgorithm;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::ffi::OsString;
use std::fs::File;
use std::io::prelude::{BufRead, Write};
use std::io::{BufReader, Lines};
use std::path::{Path, PathBuf};
use std::time::Instant;

mod cascade_helper;
use cascade_helper::create_cascade;

mod clubcard_helper;
use clubcard_helper::create_clubcard;

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
    lines: Option<Lines<BufReader<File>>>,
    reason_set: ReasonSet,
}

impl RevokedSerialAndReasonIterator {
    fn new(path: &Path, reason_set: ReasonSet) -> Self {
        Self {
            lines: Some(BufReader::new(File::open(path).unwrap()).lines()),
            reason_set,
        }
    }

    fn empty(reason_set: ReasonSet) -> Self {
        Self {
            lines: None,
            reason_set,
        }
    }

    fn skip_reason(&self, reason: &Reason) -> bool {
        match self.reason_set {
            ReasonSet::All => false,
            ReasonSet::Specified => *reason == Reason::Unspecified,
            ReasonSet::Priority => !matches!(
                *reason,
                Reason::KeyCompromise | Reason::CessationOfOperation | Reason::PrivilegeWithdrawn
            ),
        }
    }
}

impl Iterator for RevokedSerialAndReasonIterator {
    type Item = (Serial, Reason);
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(mut line) = self.lines.as_mut()?.next().transpose().expect("IO error") {
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
    date: u64,
}

impl KnownSerialIterator {
    fn new(path: &Path) -> Self {
        Self {
            lines: BufReader::new(File::open(path).unwrap()).lines(),
            date: 0,
        }
    }
}

impl Iterator for KnownSerialIterator {
    type Item = (u64, String);
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(line) = self.lines.next().transpose().expect("io error") {
            if let Some(timestamp) = line.strip_prefix("@") {
                self.date = u64::from_str_radix(timestamp, 16).expect("malformed date");
                continue;
            }
            return Some((self.date, line));
        }
        None
    }
}

fn decode_issuer(s: &str) -> [u8; 32] {
    base64::decode_config(s, base64::URL_SAFE)
        .expect("found invalid issuer id: not url-safe base64.")
        .try_into()
        .expect("found invalid issuer id: not 32 bytes.")
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
) -> Vec<(OsString, Option<PathBuf>, PathBuf)> {
    let known_files = Path::read_dir(known_dir).unwrap();
    let known_issuers: Vec<OsString> = known_files
        .filter_map(|x| x.ok())
        .map(|x| x.file_name())
        .collect();

    let mut pairs = vec![];
    for issuer in known_issuers {
        let k_file = known_dir.join(&issuer);
        let r_file = revoked_dir.join(&issuer);
        if r_file.exists() {
            pairs.push((issuer, Some(r_file), k_file));
        } else {
            pairs.push((issuer, None, k_file));
        }
    }

    pairs
}

fn size_lower_bound(ok_count: usize, revoked_count: usize) -> f64 {
    let r = revoked_count as f64;
    let n = (ok_count + revoked_count) as f64;
    let entropy = if revoked_count == 0 || ok_count == 0 {
        0.0
    } else {
        let p = r / n;
        -p * p.log2() - (1.0 - p) * (1.0 - p).log2()
    };
    // Any function that can encode an arbitrary r element subset of an n element set needs
    // an output of length ~log(n choose r) bits. Stirling's approximation to n! implies
    // that log(n choose r) can be approximated by n*H(r/n) where H is the binary entropy
    // function.
    n * entropy
}

#[derive(Default)]
struct BlockStats {
    exact_revoked_count: usize,
    approx_ok_count: usize,
    reasons: ReasonCodeHistogram,
    split_by_issuer_lower_bound: f64,
    split_by_issuer_and_expiry_lower_bound: f64,
}

impl BlockStats {
    fn merge(mut self, other: Self) -> Self {
        self.exact_revoked_count += other.exact_revoked_count;
        self.approx_ok_count += other.approx_ok_count;
        self.reasons = self.reasons.merge(other.reasons);
        self.split_by_issuer_lower_bound += other.split_by_issuer_lower_bound;
        self.split_by_issuer_and_expiry_lower_bound += other.split_by_issuer_and_expiry_lower_bound;
        self
    }
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
) -> BlockStats {
    let mut known_revoked_serial_set = HashSet::new();
    let mut reasons = ReasonCodeHistogram::default();

    let mut approx_counts = HashMap::<u64, (usize, usize)>::new();

    let revoked_serial_to_reason_map: HashMap<Serial, Reason> = revoked_serials_and_reasons
        .map(|iter| iter.into())
        .unwrap_or_default();

    for (date, serial) in known_serials {
        let (approx_ok_count, approx_revoked_count) = approx_counts.entry(date).or_insert((0, 0));
        if let Some(reason) = revoked_serial_to_reason_map.get(serial.as_str()) {
            known_revoked_serial_set.insert(serial);
            reasons.add(*reason);
            *approx_revoked_count += 1;
        } else {
            *approx_ok_count += 1;
        }
    }

    let mut approx_ok_count = 0;
    let mut split_by_issuer_and_expiry_lower_bound = 0.0;
    for (block_approx_ok_count, block_approx_revoked_count) in approx_counts.values() {
        approx_ok_count += block_approx_ok_count;
        split_by_issuer_and_expiry_lower_bound +=
            size_lower_bound(*block_approx_ok_count, *block_approx_revoked_count);
    }

    let exact_revoked_count = known_revoked_serial_set.len();
    let split_by_issuer_lower_bound = size_lower_bound(approx_ok_count, exact_revoked_count);

    BlockStats {
        exact_revoked_count,
        approx_ok_count,
        reasons,
        split_by_issuer_lower_bound,
        split_by_issuer_and_expiry_lower_bound,
    }
}

/// `count_all` performs a parallel iteration over file pairs, applies
/// `count` to each pair, and sums up the results.
fn count_all(
    revoked_dir: &Path,
    known_dir: &Path,
    reason_set: ReasonSet,
    output_csv_path: Option<&Path>,
) -> BlockStats {
    let mut counts: Vec<(OsString, BlockStats)> = list_issuer_file_pairs(revoked_dir, known_dir)
        .par_iter()
        .map(|pair| {
            let (issuer, revoked_file, known_file) = pair;
            let revoked_serials_and_reasons = revoked_file
                .as_ref()
                .map(|x| RevokedSerialAndReasonIterator::new(x, reason_set));
            let known_serials = KnownSerialIterator::new(known_file);
            (
                issuer.clone(),
                count(revoked_serials_and_reasons, known_serials),
            )
        })
        .collect();

    if let Some(output_csv_path) = output_csv_path {
        let mut output_csv = File::create(output_csv_path)
            .expect("could not open output file for reason code counts");
        writeln!(output_csv, "issuer_spki_hash,unspecified,key_compromise,privilege_withdrawn,affiliation_changed,superseded,cessation_of_operation,revoked_certificates,non_revoked_certificates").expect("could not write reason code count line");
        for (issuer, block_stats) in &counts {
            let reasons = &block_stats.reasons;
            writeln!(
                output_csv,
                "{issuer},{unspecified},{key_compromise},{privilege_withdrawn},{affiliation_changed},{superseded},{cessation},{revoked},{non_revoked}",
                issuer = issuer.to_str().unwrap(),
                unspecified = reasons.unspecified,
                key_compromise = reasons.key_compromise,
                privilege_withdrawn = reasons.privilege_withdrawn,
                affiliation_changed = reasons.affiliation_changed,
                superseded = reasons.superseded,
                cessation = reasons.cessation_of_operation,
                revoked = block_stats.exact_revoked_count,
                non_revoked = block_stats.approx_ok_count,
            )
            .expect("could not write reason code count line");
        }
    }
    counts
        .drain(..)
        .map(|x| x.1)
        .reduce(|a, b| a.merge(b))
        .unwrap_or_default()
}

trait FilterBuilder {
    type ExcludeSetType;
    type OutputType;

    fn include(
        &mut self,
        issuer: &[u8; 32],
        revoked_serials_and_reasons: RevokedSerialAndReasonIterator,
        known_serials: KnownSerialIterator,
    );

    fn exclude(
        &self,
        issuer: &[u8; 32],
        revoked_serials_and_reasons: Option<RevokedSerialAndReasonIterator>,
        known_serials: KnownSerialIterator,
    ) -> Self::ExcludeSetType;

    fn collect_exclude_sets(&mut self, exclude_sets: Vec<Self::ExcludeSetType>);

    fn finalize(self) -> Self::OutputType;

    /// `include_all` performs a serial iteration over file pairs, and applies
    /// `include` to each pair.
    fn include_all(&mut self, revoked_dir: &Path, known_dir: &Path, reason_set: ReasonSet) {
        // Include file pairs with a revoked component. Must be done serially, as
        // CascadeBuilder::include takes &mut self.
        for pair in list_issuer_file_pairs(revoked_dir, known_dir).iter() {
            if let (issuer, Some(revoked_file), known_file) = pair {
                let issuer_bytes =
                    decode_issuer(issuer.to_str().expect("non-unicode issuer string"));
                self.include(
                    &issuer_bytes,
                    RevokedSerialAndReasonIterator::new(revoked_file, reason_set),
                    KnownSerialIterator::new(known_file),
                );
            }
        }
    }

    /// `exclude_all` performs a parallel iteration over file pairs, and applies
    /// `exclude` to each pair and empties the returned `ExcludeSet`s into the builder.
    fn exclude_all(&mut self, revoked_dir: &Path, known_dir: &Path, reason_set: ReasonSet)
    where
        Self::ExcludeSetType: Send,
        Self: Sync,
    {
        let exclude_sets: Vec<Self::ExcludeSetType> =
            list_issuer_file_pairs(revoked_dir, known_dir)
                .par_iter()
                .map(|pair| {
                    let (issuer, revoked_file, known_file) = pair;
                    let issuer_bytes =
                        decode_issuer(issuer.to_str().expect("non-unicode issuer string"));
                    let revoked_serials_and_reasons = revoked_file
                        .as_ref()
                        .map(|x| RevokedSerialAndReasonIterator::new(x, reason_set));
                    let known_serials = KnownSerialIterator::new(known_file);
                    self.exclude(&issuer_bytes, revoked_serials_and_reasons, known_serials)
                })
                .collect();

        self.collect_exclude_sets(exclude_sets);
    }
}

trait CheckableFilter {
    /// `check` verifies that a cascade labels items correctly.
    fn check(
        &self,
        issuer: &[u8; 32],
        revoked_serials_and_reasons: Option<RevokedSerialAndReasonIterator>,
        known_serials: KnownSerialIterator,
    );

    /// `check_all` performs a parallel iteration over file pairs, and applies
    /// `check` to each pair.
    fn check_all(&self, revoked_dir: &Path, known_dir: &Path, reason_set: ReasonSet)
    where
        Self: Sync,
    {
        list_issuer_file_pairs(revoked_dir, known_dir)
            .par_iter()
            .for_each(|pair| {
                let (issuer, revoked_file, known_file) = pair;
                let issuer_bytes =
                    decode_issuer(issuer.to_str().expect("non-unicode issuer string"));
                let revoked_serials_and_reasons = revoked_file
                    .as_ref()
                    .map(|x| RevokedSerialAndReasonIterator::new(x, reason_set));
                let known_serials = KnownSerialIterator::new(known_file);
                self.check(&issuer_bytes, revoked_serials_and_reasons, known_serials);
            });
    }
}

/// `write_revset_and_delta` writes a revset and a delta between revsets to disk
///
/// A revset is a representation of the set R (CRLite keys corresponding to known-revoked certificates).
///
/// Revsets are only consumed by this program. Their format is subject to change (we currently
/// bincode a HashSet of CRLite keys).
///
/// The delta is output in the same form as the /revoked/ directory.
///
/// # Arguments
/// * output_delta_dir: where to write the delta update.
/// * output_revset_file: where to write the revset.
/// * prev_revset_file: where to find a revset produced by a previous run of this program.
/// * revoked_dir: the directory where lists of revoked serials can be found.
/// * known_dir: the directory where lists of known serials can be found.
/// * statsd_client: optional statsd client
///
fn write_revset_and_delta(
    output_delta_dir: &Path,
    output_revset_file: &Path,
    prev_revset_file: &Path,
    revoked_dir: &Path,
    known_dir: &Path,
    reason_set: ReasonSet,
    statsd_client: Option<&statsd::Client>,
) {
    let prev_revset: HashSet<Vec<u8>> = match std::fs::read(prev_revset_file)
        .as_deref()
        .map(bincode::deserialize)
    {
        Ok(Ok(prev_revset)) => prev_revset,
        _ => {
            warn!("Could not load previous revset. Stash file will be large.");
            Default::default()
        }
    };
    let mut revset: HashSet<Vec<u8>> = HashSet::new();

    for pair in list_issuer_file_pairs(revoked_dir, known_dir).iter() {
        if let (issuer, Some(revoked_file), known_file) = pair {
            let issuer_bytes = decode_issuer(issuer.to_str().expect("non-unicode issuer string"));
            let revoked_serials: HashMap<Serial, Reason> =
                RevokedSerialAndReasonIterator::new(revoked_file, reason_set).into();
            let known_revoked_serials = KnownSerialIterator::new(known_file)
                .filter_map(|(_expiry, serial)| revoked_serials.get_key_value(&serial));
            let mut per_issuer_delta_file = File::create(output_delta_dir.join(issuer))
                .expect("could not create per-issuer delta file");
            for (serial, reason) in known_revoked_serials {
                let serial_bytes = decode_serial(serial);
                let key = crlite_key(&issuer_bytes, &serial_bytes);
                if !prev_revset.contains(&key) {
                    writeln!(per_issuer_delta_file, "{:02x}{}", (*reason) as u8, serial)
                        .expect("Could not write delta entry");
                }
                revset.insert(key);
            }
        }
    }

    let revset_bytes = bincode::serialize(&revset).unwrap();
    info!("Revset is {} bytes", revset_bytes.len());
    std::fs::write(output_revset_file, &revset_bytes).expect("can't write revset file");

    if let Some(client) = statsd_client {
        client.gauge("revset_size", revset_bytes.len() as f64);
    }
}

/// A stash file represents the change between revsets from different runs.
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
fn write_stash(
    output_stash_file: &Path,
    delta_dir: &Path,
    reason_set: ReasonSet,
    statsd_client: Option<&statsd::Client>,
) {
    let delta_files = Path::read_dir(delta_dir).unwrap();
    let delta_issuers: Vec<OsString> = delta_files
        .filter_map(|x| x.ok())
        .map(|x| x.file_name())
        .collect();

    let mut stash_bytes = vec![];
    for issuer in delta_issuers {
        let issuer_bytes = decode_issuer(issuer.to_str().expect("non-unicode issuer string"));
        let delta_file = delta_dir.join(&issuer);
        let delta_serial_set: HashSet<Serial> =
            RevokedSerialAndReasonIterator::new(&delta_file, reason_set).into();
        if !delta_serial_set.is_empty() {
            stash_bytes.extend((delta_serial_set.len() as u32).to_le_bytes());
            stash_bytes.push(issuer_bytes.len() as u8);
            stash_bytes.extend_from_slice(&issuer_bytes);
            for serial_str in delta_serial_set {
                let serial = decode_serial(&serial_str);
                stash_bytes.push(serial.len() as u8);
                stash_bytes.extend_from_slice(serial.as_ref());
            }
        }
    }

    info!("Stash is {} bytes", stash_bytes.len());
    std::fs::write(output_stash_file, &stash_bytes).expect("can't write stash file");

    if let Some(client) = statsd_client {
        client.gauge("stash_size", stash_bytes.len() as f64);
    }
}

#[derive(clap::ValueEnum, Copy, Clone, PartialEq)]
enum FilterType {
    Cascade,
    Clubcard,
}

#[derive(Parser)]
struct Cli {
    #[clap(long, parse(from_os_str), default_value = "./known/")]
    known: PathBuf,
    #[clap(long, parse(from_os_str), default_value = "./revoked/")]
    revoked: PathBuf,
    #[clap(long, parse(from_os_str), default_value = "./prev_revset.bin")]
    prev_revset: PathBuf,
    #[clap(long, parse(from_os_str), default_value = "./ct-logs.json")]
    ct_logs_json: PathBuf,
    #[clap(long, parse(from_os_str), default_value = ".")]
    outdir: PathBuf,
    #[clap(long, value_enum, default_value = "all")]
    reason_set: ReasonSet,
    #[clap(long, value_enum, default_value = "all")]
    delta_reason_set: ReasonSet,
    #[clap(long)]
    statsd_host: Option<String>,
    #[clap(long)]
    murmurhash3: bool,
    #[clap(long, value_enum, default_value = "cascade")]
    filter_type: FilterType,
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
    let delta_reason_set = args.delta_reason_set;
    let filter_type = args.filter_type;
    let ct_logs_json = &args.ct_logs_json;

    let out_dir = &args.outdir;
    let filter_file = &out_dir.join("filter");
    let stash_file = &out_dir.join("filter.stash");
    let revset_file = &out_dir.join("revset.bin");
    let delta_dir = &out_dir.join("delta");
    let delta_filter_file = &out_dir.join("filter.delta");
    let reason_codes_csv_file = &out_dir.join("reason_codes.csv");

    if !known_dir.exists() {
        error!("{} not found", known_dir.display());
        err = true;
    }
    if !revoked_dir.exists() {
        error!("{} not found", revoked_dir.display());
        err = true;
    }
    if filter_type == FilterType::Clubcard && !ct_logs_json.exists() {
        error!("{} not found", ct_logs_json.display());
        err = true;
    }

    if args.clobber {
        if out_dir.exists() && std::fs::remove_dir_all(out_dir).is_err() {
            error!("could not clobber output directory");
            err = true;
        }
    } else {
        for f in [
            filter_file,
            stash_file,
            revset_file,
            delta_dir,
            delta_filter_file,
        ] {
            if f.exists() {
                error!(
                    "{} exists! Will not overwrite without --clobber.",
                    f.display()
                );
                err = true;
            }
        }
    }
    if !out_dir.exists() && std::fs::create_dir_all(out_dir).is_err() {
        error!("Could not create out directory: {}", out_dir.display());
        err = true;
    }
    if !delta_dir.exists() && std::fs::create_dir_all(delta_dir).is_err() {
        error!("Could not create delta directory: {}", delta_dir.display());
        err = true;
    }
    if err {
        return;
    }

    let hash_alg = match args.murmurhash3 {
        true => HashAlgorithm::MurmurHash3,
        false => HashAlgorithm::Sha256,
    };

    let statsd_prefix = match (filter_type, reason_set) {
        (FilterType::Cascade, ReasonSet::All) => "crlite.generate",
        (FilterType::Cascade, ReasonSet::Specified) => "crlite.generate.specified_reasons",
        (FilterType::Cascade, ReasonSet::Priority) => "crlite.generate.priority_reasons",
        (FilterType::Clubcard, ReasonSet::All) => "crlite.clubcard.generate",
        (FilterType::Clubcard, ReasonSet::Specified) => {
            "crlite.clubcard.generate.specified_reasons"
        }
        (FilterType::Clubcard, ReasonSet::Priority) => "crlite.clubcard.generate.priority_reasons",
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

    info!("Counting serials");
    let filter_stats = count_all(
        revoked_dir,
        known_dir,
        reason_set,
        Some(reason_codes_csv_file),
    );
    info!(
        "Lower bound when splitting by issuer is {:.0} bytes",
        filter_stats.split_by_issuer_lower_bound / 8.0
    );
    info!(
        "Lower bound when splitting by issuer and expiry is {:.0} bytes",
        filter_stats.split_by_issuer_and_expiry_lower_bound / 8.0
    );

    info!(
        "Found {} 'revoked' and {} 'not revoked' serial numbers",
        filter_stats.exact_revoked_count, filter_stats.approx_ok_count
    );
    info!("Revocation reason codes: {:#?}", filter_stats.reasons);

    let timer_start = Instant::now();
    let filter_bytes = match filter_type {
        FilterType::Clubcard => {
            info!("Generating clubcard");
            create_clubcard(
                filter_file,
                revoked_dir,
                known_dir,
                ct_logs_json,
                reason_set,
            )
        }
        FilterType::Cascade => {
            info!("Generating cascade");
            create_cascade(
                filter_file,
                filter_stats.exact_revoked_count,
                filter_stats.approx_ok_count,
                revoked_dir,
                known_dir,
                hash_alg,
                reason_set,
            )
        }
    };
    let timer_finish = Instant::now() - timer_start;
    info!("Finished in {} seconds", timer_finish.as_secs());

    info!("Generating stash file");
    let timer_start = Instant::now();
    write_revset_and_delta(
        delta_dir,
        revset_file,
        prev_revset_file,
        revoked_dir,
        known_dir,
        delta_reason_set,
        statsd_client.as_ref(),
    );

    write_stash(
        stash_file,
        delta_dir,
        delta_reason_set,
        statsd_client.as_ref(),
    );
    let timer_finish = Instant::now() - timer_start;
    info!("Finished in {} seconds", timer_finish.as_secs());

    info!("Counting delta serials");
    let delta_stats = count_all(delta_dir, known_dir, delta_reason_set, None);
    info!(
        "Lower bound is {:.0} bytes",
        delta_stats.split_by_issuer_lower_bound / 8.0
    );
    info!(
        "Lower bound is {:.0} bytes",
        delta_stats.split_by_issuer_and_expiry_lower_bound / 8.0
    );

    info!(
        "Found {} 'revoked' serial numbers in delta",
        delta_stats.exact_revoked_count
    );
    info!("Revocation reason codes: {:#?}", delta_stats.reasons);

    info!("Generating delta filter");
    let timer_start = Instant::now();
    let delta_filter_bytes = match filter_type {
        FilterType::Clubcard => {
            info!("Generating clubcard");
            create_clubcard(
                delta_filter_file,
                delta_dir,
                known_dir,
                ct_logs_json,
                delta_reason_set,
            )
        }
        FilterType::Cascade => {
            info!("Generating cascade");
            create_cascade(
                delta_filter_file,
                delta_stats.exact_revoked_count,
                delta_stats.approx_ok_count,
                delta_dir,
                known_dir,
                hash_alg,
                delta_reason_set,
            )
        }
    };
    let timer_finish = Instant::now() - timer_start;
    info!("Finished in {} seconds", timer_finish.as_secs());

    if let Some(client) = statsd_client {
        client.gauge("time", timer_finish.as_secs() as f64);
        client.gauge("filter_size", filter_bytes.len() as f64);
        client.gauge(
            "filter_by_issuer_lower_bound",
            filter_stats.split_by_issuer_lower_bound,
        );
        client.gauge(
            "filter_by_issuer_and_expiry_lower_bound",
            filter_stats.split_by_issuer_and_expiry_lower_bound,
        );
        client.gauge("not_revoked", filter_stats.approx_ok_count as f64);
        client.gauge("revoked", filter_stats.exact_revoked_count as f64);
        client.gauge("delta_filter_size", delta_filter_bytes.len() as f64);
        client.gauge(
            "delta_by_issuer_lower_bound",
            delta_stats.split_by_issuer_lower_bound,
        );
        client.gauge(
            "delta_by_issuer_and_expiry_lower_bound",
            delta_stats.split_by_issuer_and_expiry_lower_bound,
        );
        client.gauge("delta_not_revoked", delta_stats.approx_ok_count as f64);
        client.gauge("delta_revoked", delta_stats.exact_revoked_count as f64);
        client.gauge(
            "revoked.unspecified",
            filter_stats.reasons.unspecified as f64,
        );
        client.gauge(
            "revoked.key_compromise",
            filter_stats.reasons.key_compromise as f64,
        );
        client.gauge(
            "revoked.ca_compromise",
            filter_stats.reasons.ca_compromise as f64,
        );
        client.gauge(
            "revoked.affiliation_changed",
            filter_stats.reasons.affiliation_changed as f64,
        );
        client.gauge("revoked.superseded", filter_stats.reasons.superseded as f64);
        client.gauge(
            "revoked.cessation_of_operation",
            filter_stats.reasons.cessation_of_operation as f64,
        );
        client.gauge(
            "revoked.certificate_hold",
            filter_stats.reasons.certificate_hold as f64,
        );
        client.gauge(
            "revoked.remove_from_crl",
            filter_stats.reasons.remove_from_crl as f64,
        );
        client.gauge(
            "revoked.privilege_withdrawn",
            filter_stats.reasons.privilege_withdrawn as f64,
        );
        client.gauge(
            "revoked.aa_compromise",
            filter_stats.reasons.aa_compromise as f64,
        );
    }

    info!("Done");
}

#[cfg(test)]
mod tests {
    use super::{
        cascade_helper::create_cascade, clubcard_helper::create_clubcard, count_all, crlite_key,
        decode_issuer, decode_serial, write_revset_and_delta, write_stash, CheckableFilter, Reason,
        ReasonSet,
    };
    use clubcard_crlite::CRLiteClubcard;
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
            std::fs::create_dir(dir.path().join("delta")).expect("could not create delta dir");
            std::fs::write(dir.path().join("ct-logs.json"), &[])
                .expect("could not create ct-logs.json");
            Self { dir }
        }

        fn known_dir(&self) -> PathBuf {
            self.dir.path().join("known")
        }

        fn revoked_dir(&self) -> PathBuf {
            self.dir.path().join("revoked")
        }

        fn ct_logs_path(&self) -> PathBuf {
            self.dir.path().join("ct-logs.json")
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
                .append(true)
                .open(self.known_dir().join(issuer))
                .expect("could not open known file");

            let mut revoked_file = std::fs::OpenOptions::new()
                .append(true)
                .open(self.revoked_dir().join(issuer))
                .expect("could not open revoked file");

            let serial_str = hex::encode(serial_bytes);
            let reason_str = hex::encode([reason as u8]);
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

        let stats = count_all(&env.revoked_dir(), &env.known_dir(), ReasonSet::All, None);
        assert_eq!(stats.approx_ok_count, 86);
        assert_eq!(stats.exact_revoked_count, 75 + 30 + 9);
        assert_eq!(stats.reasons.unspecified, 75);
        assert_eq!(stats.reasons.key_compromise, 30);
        assert_eq!(stats.reasons.ca_compromise, 0);
        assert_eq!(stats.reasons.affiliation_changed, 0);
        assert_eq!(stats.reasons.superseded, 0);
        assert_eq!(stats.reasons.cessation_of_operation, 0);
        assert_eq!(stats.reasons.certificate_hold, 0);
        assert_eq!(stats.reasons.remove_from_crl, 0);
        assert_eq!(stats.reasons.privilege_withdrawn, 9);
        assert_eq!(stats.reasons.aa_compromise, 0);

        let stats = count_all(
            &env.revoked_dir(),
            &env.known_dir(),
            ReasonSet::Specified,
            None,
        );
        assert_eq!(stats.approx_ok_count, 86 + 75);
        assert_eq!(stats.exact_revoked_count, 30 + 9);
        assert_eq!(stats.reasons.unspecified, 0);
        assert_eq!(stats.reasons.key_compromise, 30);
        assert_eq!(stats.reasons.ca_compromise, 0);
        assert_eq!(stats.reasons.affiliation_changed, 0);
        assert_eq!(stats.reasons.superseded, 0);
        assert_eq!(stats.reasons.cessation_of_operation, 0);
        assert_eq!(stats.reasons.certificate_hold, 0);
        assert_eq!(stats.reasons.remove_from_crl, 0);
        assert_eq!(stats.reasons.privilege_withdrawn, 9);
        assert_eq!(stats.reasons.aa_compromise, 0);

        let stats = count_all(
            &env.revoked_dir(),
            &env.known_dir(),
            ReasonSet::Priority,
            None,
        );
        assert_eq!(stats.approx_ok_count, 86 + 75);
        assert_eq!(stats.exact_revoked_count, 30 + 9);
        assert_eq!(stats.reasons.unspecified, 0);
        assert_eq!(stats.reasons.key_compromise, 30);
        assert_eq!(stats.reasons.ca_compromise, 0);
        assert_eq!(stats.reasons.affiliation_changed, 0);
        assert_eq!(stats.reasons.superseded, 0);
        assert_eq!(stats.reasons.cessation_of_operation, 0);
        assert_eq!(stats.reasons.certificate_hold, 0);
        assert_eq!(stats.reasons.remove_from_crl, 0);
        assert_eq!(stats.reasons.privilege_withdrawn, 9);
        assert_eq!(stats.reasons.aa_compromise, 0);
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
        let delta_dir = env.dir.path().join("delta");

        let stats = count_all(&env.revoked_dir(), &env.known_dir(), ReasonSet::All, None);
        create_cascade(
            &filter_file,
            stats.exact_revoked_count,
            stats.approx_ok_count,
            &env.revoked_dir(),
            &env.known_dir(),
            HashAlgorithm::Sha256,
            ReasonSet::All,
        );

        write_revset_and_delta(
            &delta_dir,
            &revset_file,
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

        write_revset_and_delta(
            &delta_dir,
            &revset_file,
            &prev_revset_file,
            &env.revoked_dir(),
            &env.known_dir(),
            ReasonSet::All,
            None,
        );

        write_stash(&stash_file, &delta_dir, ReasonSet::All, None);

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
        write_revset_and_delta(
            &delta_dir,
            &revset_file,
            &prev_revset_file,
            &env.revoked_dir(),
            &env.known_dir(),
            ReasonSet::Specified,
            None,
        );

        write_stash(&stash_file, &delta_dir, ReasonSet::Specified, None);

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
        let stats = count_all(
            &env.revoked_dir(),
            &env.known_dir(),
            ReasonSet::Specified,
            None,
        );
        create_cascade(
            &filter_file,
            stats.exact_revoked_count,
            stats.approx_ok_count,
            &env.revoked_dir(),
            &env.known_dir(),
            HashAlgorithm::Sha256,
            ReasonSet::Specified,
        );

        let filter_bytes = std::fs::read(&filter_file).expect("could not read filter file");
        let cascade = Cascade::from_bytes(filter_bytes)
            .expect("cannot deserialize cascade")
            .expect("cascade should be some");

        // Checking with ReasonSet::All will panic
        cascade.check_all(&env.revoked_dir(), &env.known_dir(), ReasonSet::All);
    }

    #[test]
    fn test_cascade() {
        let env = TestEnv::new();
        let issuer = env.add_issuer();
        for _ in 1..=(1 << 16) {
            env.add_serial(&issuer);
        }
        for _ in 1..=(1 << 10) {
            env.add_revoked_serial(&issuer, Reason::Unspecified);
        }

        let filter_file = env.dir.path().join("filter");

        let stats = count_all(&env.revoked_dir(), &env.known_dir(), ReasonSet::All, None);

        let cascade_bytes = create_cascade(
            &filter_file,
            stats.exact_revoked_count,
            stats.approx_ok_count,
            &env.revoked_dir(),
            &env.known_dir(),
            HashAlgorithm::Sha256,
            ReasonSet::All,
        );
        assert!(
            CRLiteClubcard::from_bytes(&cascade_bytes).is_err(),
            "A Cascade should not deserialize as a Clubcard"
        );
    }

    #[test]
    fn test_clubcard() {
        let env = TestEnv::new();
        let issuer = env.add_issuer();
        for _ in 1..=(1 << 16) {
            env.add_serial(&issuer);
        }
        for _ in 1..=(1 << 10) {
            env.add_revoked_serial(&issuer, Reason::Unspecified);
        }

        let filter_file = env.dir.path().join("filter");
        let clubcard_bytes = create_clubcard(
            &filter_file,
            &env.revoked_dir(),
            &env.known_dir(),
            &env.ct_logs_path(),
            ReasonSet::All,
        );
        assert!(
            Cascade::from_bytes(clubcard_bytes).is_err(),
            "A Clubcard should not deserialize as a Cascade"
        );
    }
}
