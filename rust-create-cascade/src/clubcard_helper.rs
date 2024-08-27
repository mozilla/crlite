/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::{
    decode_serial, list_issuer_file_pairs, CheckableFilter, FilterBuilder, KnownSerialIterator,
    ReasonSet, RevokedSerialAndReasonIterator, Serial,
};
use clubcard::{
    builder::{ApproximateRibbon, ClubcardBuilder, ExactRibbon},
    crlite::CRLiteKey,
    Clubcard,
};

use log::*;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::collections::HashSet;
use std::fs::File;
use std::io::prelude::Write;
use std::path::Path;

fn clubcard_do_one_issuer(
    clubcard: &ClubcardBuilder<4, CRLiteKey>,
    issuer: &[u8; 32],
    revoked_serials_and_reasons: RevokedSerialAndReasonIterator,
    known_serials: KnownSerialIterator,
) -> ApproximateRibbon<4, CRLiteKey> {
    let mut revoked_serial_set: HashSet<Serial> = revoked_serials_and_reasons.into();

    let mut ribbon_builder = clubcard.get_approx_builder(&issuer);
    let mut universe_size = 0;
    for serial in known_serials {
        universe_size += 1;
        if revoked_serial_set.contains(&serial) {
            let key = CRLiteKey::revoked(*issuer, decode_serial(&serial));
            ribbon_builder.insert(key);
            // Ensure that we do not attempt to include this issuer+serial again.
            revoked_serial_set.remove(&serial);
        }
    }
    ribbon_builder.set_universe_size(universe_size);
    ribbon_builder.into()
}

impl FilterBuilder for ClubcardBuilder<4, CRLiteKey> {
    type ExcludeSetType = ExactRibbon<4, CRLiteKey>;
    type OutputType = Clubcard;

    fn include(
        &mut self,
        _issuer: &[u8; 32],
        _revoked_serials_and_reasons: RevokedSerialAndReasonIterator,
        _known_serials: KnownSerialIterator,
    ) {
        // The FilterBuilder trait assumes that include_all() performs a serial iteration over
        // shards and defines include() as taking a &mut self reference. Clubcard shards can be
        // built in parallel with only an &self reference. So we override include_all() and never
        // call include().
        unimplemented!();
    }

    fn include_all(&mut self, revoked_dir: &Path, known_dir: &Path, reason_set: ReasonSet) {
        let ribbons: Vec<ApproximateRibbon<4, CRLiteKey>> =
            list_issuer_file_pairs(revoked_dir, known_dir)
                .par_iter()
                .map(|pair| {
                    if let (issuer, Some(revoked_file), known_file) = pair {
                        Some(clubcard_do_one_issuer(
                            self,
                            issuer,
                            RevokedSerialAndReasonIterator::new(revoked_file, reason_set),
                            KnownSerialIterator::new(known_file),
                        ))
                    } else {
                        None
                    }
                })
                .flatten()
                .collect();

        ClubcardBuilder::collect_approx_ribbons(self, ribbons);
    }

    fn exclude(
        &self,
        issuer: &[u8; 32],
        revoked_serials_and_reasons: Option<RevokedSerialAndReasonIterator>,
        known_serials: KnownSerialIterator,
    ) -> Self::ExcludeSetType {
        let mut ribbon_builder = ClubcardBuilder::get_exact_builder(self, &issuer);

        let revoked_serial_set: HashSet<Serial> = revoked_serials_and_reasons
            .map(|iter| iter.into())
            .unwrap_or_default();

        let non_revoked_serials = known_serials.filter(|x| !revoked_serial_set.contains(x));

        for serial in &revoked_serial_set {
            let key = CRLiteKey::revoked(*issuer, decode_serial(serial));
            ribbon_builder.insert(key);
        }

        for serial in non_revoked_serials {
            let key = CRLiteKey::not_revoked(*issuer, decode_serial(&serial));
            ribbon_builder.insert(key);
        }
        ribbon_builder.into()
    }

    fn collect_exclude_sets(&mut self, exclude_sets: Vec<Self::ExcludeSetType>) {
        self.collect_exact_ribbons(exclude_sets);
    }

    fn finalize(self) -> Self::OutputType {
        ClubcardBuilder::build(self)
    }
}

impl CheckableFilter for Clubcard {
    fn check(
        &self,
        issuer: &[u8; 32],
        revoked_serials_and_reasons: Option<RevokedSerialAndReasonIterator>,
        known_serials: KnownSerialIterator,
    ) {
        let revoked_serial_set: HashSet<Serial> = revoked_serials_and_reasons
            .map(|iter| iter.into())
            .unwrap_or_default();

        for serial in known_serials {
            let key = CRLiteKey::query(*issuer, decode_serial(&serial));
            assert!(Clubcard::contains(self, &key) == revoked_serial_set.contains(&serial))
        }
    }
}

pub fn create_clubcard(
    out_file: &Path,
    revoked_dir: &Path,
    known_dir: &Path,
    reason_set: ReasonSet,
) -> Vec<u8> {
    let mut builder = ClubcardBuilder::new();

    info!("Processing revoked serials");
    FilterBuilder::include_all(&mut builder, revoked_dir, known_dir, reason_set);

    info!("Processing non-revoked serials");
    FilterBuilder::exclude_all(&mut builder, revoked_dir, known_dir, reason_set);

    info!("Eliminating false positives");
    let clubcard = FilterBuilder::finalize(builder);

    info!("Generated {}", clubcard);

    info!("Testing serialization");
    let clubcard_bytes = clubcard.to_bytes().expect("cannot serialize clubcard");
    info!("Clubcard is {} bytes", clubcard_bytes.len());

    let clubcard = Clubcard::from_bytes(&clubcard_bytes).expect("cannot deserialize clubcard");

    info!("Verifying clubcard");
    clubcard.check_all(revoked_dir, known_dir, reason_set);

    info!("Writing clubcard to {}", out_file.display());
    let mut filter_writer = File::create(out_file).expect("cannot open file");
    filter_writer
        .write_all(&clubcard_bytes)
        .expect("can't write file");

    clubcard_bytes
}
