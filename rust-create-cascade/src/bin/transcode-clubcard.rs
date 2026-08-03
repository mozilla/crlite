/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! # transcode-clubcard
//!
//! Reads a CRLite clubcard and writes an equivalent clubcard in a different serialization
//! format.
//!
//! A run of `rust-create-cascade` emits a single encoding. We want to publish both the V3
//! and the V4 encoding of each clubcard while clients migrate, so the workflow builds the
//! V3 encoding and uses this program to derive the V4 copy from it.

extern crate clap;
extern crate clubcard_crlite;
extern crate log;
extern crate stderrlog;

use clap::Parser;
use clubcard_crlite::CRLiteClubcard;
use log::*;
use std::path::PathBuf;

/// Serialization format for clubcard filters.
///
/// `bincode` is the legacy V3 encoding; `tls` is the V4 encoding that uses a
/// TLS-presentation-language-style codec.
#[derive(clap::ValueEnum, Copy, Clone, PartialEq)]
enum ClubcardEncoding {
    Bincode,
    Tls,
}

impl From<ClubcardEncoding> for clubcard_crlite::Encoding {
    fn from(encoding: ClubcardEncoding) -> clubcard_crlite::Encoding {
        match encoding {
            ClubcardEncoding::Bincode => clubcard_crlite::Encoding::V3,
            ClubcardEncoding::Tls => clubcard_crlite::Encoding::V4,
        }
    }
}

#[derive(Parser)]
struct Cli {
    /// Clubcard to read. Its encoding is taken from its header, not from --encoding.
    #[clap(long, parse(from_os_str))]
    input: PathBuf,
    /// Where to write the re-encoded clubcard.
    #[clap(long, parse(from_os_str))]
    output: PathBuf,
    #[clap(long, value_enum, default_value = "tls")]
    encoding: ClubcardEncoding,
    #[clap(long)]
    clobber: bool,
    #[clap(short = 'v', parse(from_occurrences))]
    verbose: usize,
}

fn main() {
    let args = Cli::parse();

    stderrlog::new()
        .module(module_path!())
        .verbosity(args.verbose)
        .init()
        .unwrap();

    if args.output.exists() && !args.clobber {
        error!(
            "{} exists! Will not overwrite without --clobber.",
            args.output.display()
        );
        std::process::exit(1);
    }

    let input_bytes = std::fs::read(&args.input).expect("cannot read input file");
    let clubcard = CRLiteClubcard::from_bytes(&input_bytes).expect("cannot deserialize clubcard");
    info!(
        "Read {} ({} bytes)",
        args.input.display(),
        input_bytes.len()
    );
    info!("{}", clubcard);

    let output_bytes = clubcard
        .to_bytes(args.encoding.into())
        .expect("cannot serialize clubcard");

    info!("Testing deserialization");
    CRLiteClubcard::from_bytes(&output_bytes).expect("cannot deserialize re-encoded clubcard");

    std::fs::write(&args.output, &output_bytes).expect("cannot write output file");
    info!(
        "Wrote {} ({} bytes)",
        args.output.display(),
        output_bytes.len()
    );
}
