/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::{
    crlite_key, decode_serial, CheckableFilter, FilterBuilder, KnownSerialIterator, ReasonSet,
    RevokedSerialAndReasonIterator, Serial,
};
use rust_cascade::{Cascade, CascadeBuilder, ExcludeSet, HashAlgorithm};

use log::*;
use std::collections::HashSet;
use std::fs::File;
use std::io::prelude::Write;
use std::path::Path;

use rand::rngs::OsRng;
use rand::RngCore;

impl FilterBuilder for CascadeBuilder {
    type ExcludeSetType = ExcludeSet;
    type OutputType = Cascade;

    /// `include` finds revoked serials that are known and includes them in the filter cascade.
    fn include(
        &mut self,
        issuer: &[u8; 32],
        revoked_serials_and_reasons: RevokedSerialAndReasonIterator,
        known_serials: KnownSerialIterator,
    ) {
        let mut revoked_serial_set: HashSet<Serial> = revoked_serials_and_reasons.into();

        for serial in known_serials {
            if revoked_serial_set.contains(&serial) {
                let key = crlite_key(issuer.as_ref(), &decode_serial(&serial));
                CascadeBuilder::include(self, key)
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
        &self,
        issuer: &[u8; 32],
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
            CascadeBuilder::exclude_threaded(self, &mut exclude_set, key);
        }
        exclude_set
    }

    fn collect_exclude_sets(&mut self, mut exclude_sets: Vec<ExcludeSet>) {
        for mut exclude_set in exclude_sets.drain(..) {
            self.collect_exclude_set(&mut exclude_set).unwrap();
        }
    }

    fn finalize(self) -> Cascade {
        *CascadeBuilder::finalize(self).unwrap()
    }
}

impl CheckableFilter for Cascade {
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
            assert_eq!(
                Cascade::has(self, crlite_key(issuer, &decode_serial(&serial))),
                revoked_serial_set.contains(&serial)
            );
        }
    }
}

/// `create_cascade` runs through the full filter generation process and returns the
/// serialized cascade
pub fn create_cascade(
    out_file: &Path,
    revoked: usize,
    not_revoked: usize,
    revoked_dir: &Path,
    known_dir: &Path,
    hash_alg: HashAlgorithm,
    reason_set: ReasonSet,
) -> Vec<u8> {
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
    FilterBuilder::include_all(&mut builder, revoked_dir, known_dir, reason_set);

    info!("Processing non-revoked serials");
    FilterBuilder::exclude_all(&mut builder, revoked_dir, known_dir, reason_set);

    info!("Eliminating false positives");
    let cascade = FilterBuilder::finalize(builder);

    info!("Testing serialization");
    let cascade_bytes = cascade.to_bytes().expect("cannot serialize cascade");
    info!("Cascade is {} bytes", cascade_bytes.len());

    if let Some(cascade) =
        Cascade::from_bytes(cascade_bytes.clone()).expect("cannot deserialize cascade")
    {
        info!("\n{}", cascade);

        info!("Verifying cascade");
        cascade.check_all(revoked_dir, known_dir, reason_set);
    } else {
        warn!("Produced empty cascade. Exiting.");
        return vec![];
    }

    info!("Writing cascade to {}", out_file.display());
    let mut filter_writer = File::create(out_file).expect("cannot open file");
    filter_writer
        .write_all(&cascade_bytes)
        .expect("can't write file");

    cascade_bytes
}
