#!/usr/bin/env python3

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import itertools
import json
import moz_crlite_lib as crlite
import os
import psutil
import statsd
import sys

import glog as log

from filtercascade import FilterCascade, fileformats
from pathlib import Path

# Structure of the stats object:
# {
#   "known"              : Int, Count of all known certs
#   "revoked"            : Int, Count of all revoked certs
#   "knownnotrevoked"    : Int, Count of all known not revoked certs
#   "knownrevoked"       : Int, Count of all known revoked certs
#   "nocrl"              : Int, Count of issuers that did not have a CRL
#   "mlbf_fprs"          : [List of Floats corresponding to the false
#                           positive rates for the layers of the MLBF]
#   "mlbf_version"       : Int, Version of the MLBF that was produced
#   "mlbf_layers"        : Int, Number of layers in the MLBF
#   "mlbf_bits"          : Int, Total bits used by the MLBF filters
#   "mlbf_filesize"      : Int, Size of the MLBF file in bytes
#   "mlbf_diffsize"      : Int, Size of the MLBF diff file (if it was produced,
#                          otherwise this field is omitted)
#   "Issuers"            : {
#     "issuer1"           : {
#       'known'           : Int, Count of known certs for this issuer
#       'revoked'         : Int, Count of revoked certs for this issuer
#       'knownnotrevoked' : Int, Count of known, not revoked certs for this issuer
#       'knownrevoked'    : Int, Count of known revoked certs for this issuer
#       'crl'             : Boolean, True if this issuer had a CRL
#     },
#     "issuer2"           : {
#         ... specific stuff about issuer2's certs and revocations ...
#     },
#     ... etc...
#   }
# }

metrics = statsd.StatsClient(
    os.getenv("statsdHost", "localhost"),
    os.getenv("statsdPort", 8125),
    prefix="create_filter_cascade",
)


def initIssuerStats(stats, issuer):
    stats["Issuers"][issuer] = {
        "known": 0,
        "revoked": 0,
        "knownnotrevoked": 0,
        "knownrevoked": 0,
        "crl": False,
    }


@metrics.timer("CreateCertLists")
def createCertLists(
    *,
    known_path,
    revoked_path,
    known_revoked_path,
    known_nonrevoked_path,
    exclude_issuer,
    stats,
):
    stats["knownrevoked"] = 0
    stats["knownnotrevoked"] = 0
    stats["revoked"] = 0
    stats["known"] = 0
    stats["nocrl"] = 0
    stats["Issuers"] = {}

    log.info(
        f"Generating revoked/nonrevoked lists {known_revoked_path} {known_nonrevoked_path} "
        + f"from {known_path} and {revoked_path}"
    )

    os.makedirs(os.path.dirname(known_revoked_path), exist_ok=True)
    os.makedirs(os.path.dirname(known_nonrevoked_path), exist_ok=True)

    with open(known_revoked_path, "wb") as revfile, open(
        known_nonrevoked_path, "wb"
    ) as nonrevfile:
        issuerPathIter = crlite.genIssuerPathObjects(
            knownPath=known_path, revokedPath=revoked_path, excludeIssuer=exclude_issuer
        )
        for issuerObj in sorted(issuerPathIter, key=lambda i: i.issuer):
            log.debug(
                f"createCertLists Processing issuerObj={issuerObj}, "
                + f"memory={psutil.virtual_memory()}"
            )
            metrics.gauge(
                "CreateCertLists.VirtualMemory.available",
                psutil.virtual_memory().available,
            )

            issuer = issuerObj.issuer
            initIssuerStats(stats, issuer)

            sets = issuerObj.load_and_make_sets(stats)

            known_nonrevoked_certs_len = len(sets["knownNotRevoked"])
            known_revoked_certs_len = len(sets["knownRevoked"])

            stats["knownnotrevoked"] += known_nonrevoked_certs_len
            stats["knownrevoked"] += known_revoked_certs_len
            stats["Issuers"][issuer]["knownnotrevoked"] = known_nonrevoked_certs_len
            stats["Issuers"][issuer]["knownrevoked"] = known_revoked_certs_len

            crlite.writeCertListForIssuer(
                file=revfile, issuer_base64=issuer, serial_list=sets["knownRevoked"]
            )
            crlite.writeCertListForIssuer(
                file=nonrevfile,
                issuer_base64=issuer,
                serial_list=sets["knownNotRevoked"],
            )

            log.debug(
                f"createCertLists issuerObj={issuerObj} KNR={known_nonrevoked_certs_len} "
                + f"KR={known_revoked_certs_len}"
            )

            metrics.incr("CreateCertLists.Issuers")
            metrics.incr("CreateCertLists.KnownRevoked", count=known_revoked_certs_len)
            metrics.incr(
                "CreateCertLists.KnownNotRevoked", count=known_nonrevoked_certs_len
            )

    # TODO: Verify any revoked issuers that had no known issuers

    log.debug(
        "R: %d K: %d KNR: %d KR: %d NOCRL: %d"
        % (
            stats["revoked"],
            stats["known"],
            stats["knownnotrevoked"],
            stats["knownrevoked"],
            stats["nocrl"],
        )
    )

    return {
        "known_nonrevoked_certs_len": stats["knownnotrevoked"],
        "known_revoked_certs_len": stats["knownrevoked"],
    }


@metrics.timer("GenerateMLBF")
def generateMLBF(args, stats, *, revoked_certs, nonrevoked_certs, nonrevoked_certs_len):
    revoked_certs_len = len(revoked_certs)

    log.info("Generating filter")
    cascade = FilterCascade(
        [], version=1, defaultHashAlg=fileformats.HashAlgorithm.MURMUR3
    )
    cascade.set_crlite_error_rates(
        include_len=revoked_certs_len, exclude_len=nonrevoked_certs_len
    )
    cascade.initialize(include=revoked_certs, exclude=nonrevoked_certs)

    stats["mlbf_fprs"] = cascade.error_rates
    stats["mlbf_version"] = cascade.version
    stats["mlbf_layers"] = cascade.layerCount()
    stats["mlbf_bits"] = cascade.bitCount()

    log.debug(
        "Filter cascade layers: {layers}, bit: {bits}".format(
            layers=cascade.layerCount(), bits=cascade.bitCount()
        )
    )
    metrics.gauge("GenerateMLBF.BitCount", cascade.bitCount())
    metrics.gauge("GenerateMLBF.LayerCount", cascade.layerCount())
    return cascade


@metrics.timer("VerifyMLBF")
def verifyMLBF(args, cascade, *, revoked_certs, nonrevoked_certs):
    # Verify generate filter
    if args.noVerify is False:
        log.info("Checking/verifying certs against MLBF")
        cascade.verify(include=revoked_certs, exclude=nonrevoked_certs)


@metrics.timer("SaveMLBF")
def saveMLBF(args, stats, cascade):
    os.makedirs(os.path.dirname(args.outFile), exist_ok=True)

    with open(args.outFile, "wb") as mlbf_file:
        log.info("Writing to file {}".format(args.outFile))
        cascade.tofile(mlbf_file)
    stats["mlbf_filesize"] = os.stat(args.outFile).st_size


@metrics.timer("FindAdditions")
def find_additions(*, old_by_issuer, new_by_issuer):
    added = {}
    old_cache = {}
    new_cache = {}

    o_issuer_b64, o_set = next(old_by_issuer)

    # Assume the issuers are in the same order
    try:
        for n_issuer_b64, n_set in new_by_issuer:
            if n_issuer_b64 == o_issuer_b64:
                diff_set = n_set - o_set
                if diff_set:
                    added[n_issuer_b64] = diff_set

                o_issuer_b64, o_set = next(old_by_issuer)
                continue

            new_cache[n_issuer_b64] = n_set
    except StopIteration:
        pass

    # If there are any remaining "new" entries, put them in the new_cache.
    for n_issuer_b64, n_set in new_by_issuer:
        new_cache[n_issuer_b64] = n_set

    # If there any remaining "old" entries, try and compare them against the
    # new_cache, otherwise track them for later. Don't forget the leftover
    # value from the uses of `next` above.
    for o_issuer_b64, o_set in itertools.chain([(o_issuer_b64, o_set)], old_by_issuer):
        if o_issuer_b64 in new_cache:
            diff_set = new_cache[o_issuer_b64] - o_set
            if diff_set:
                added[o_issuer_b64] = diff_set
            del new_cache[o_issuer_b64]
            continue
        old_cache[o_issuer_b64] = o_set

    # Anything still in new_cache is actually added and new
    for n_issuer_b64, n_set in new_cache.items():
        assert n_issuer_b64 not in added, f"{n_issuer_b64} shouldn't be in added!"
        added[n_issuer_b64] = n_set

    if len(old_cache) > 0:
        # We don't care about removals, but log a debug statement if it matters
        log.debug(
            "find_additions: old_cache indicates a removal of "
            + f"{len(old_cache)} entries from keys: {old_cache.keys()}"
        )
    return added


def parseArgs(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("id", help="CT baseline identifier", metavar=("ID"))
    parser.add_argument(
        "-previd",
        type=Path,
        help="Previous identifier to use for diff",
        metavar=("DIFFID"),
    )
    parser.add_argument(
        "-certPath",
        type=Path,
        help="Directory containing CT data.",
        default="/ct/processing",
    )
    parser.add_argument(
        "-outDirName",
        type=Path,
        help="Name of the directory to store output in. Default=mlbf/",
        default="mlbf",
    )
    parser.add_argument(
        "-knownPath",
        type=Path,
        help="Directory containing known unexpired serials. Like ID/known/",
    )
    parser.add_argument(
        "-revokedPath",
        type=Path,
        help="Directory containing known revoked serials, like ID/revoked/",
    )
    parser.add_argument("-capacity", type=float, default="1.1", help="MLBF capacity.")
    parser.add_argument(
        "-excludeIssuer", nargs="*", default=[], help="Exclude the specified Issuers"
    )
    parser.add_argument(
        "-onlyUseCache",
        help="Load revoked/non-revoked sorted certs from cache files, do not read the knownPath "
        + "or revokedPath folders",
        action="store_true",
    )
    parser.add_argument("-noVerify", help="Skip MLBF verification", action="store_true")
    args = parser.parse_args(argv)
    args.outFile = args.certPath / args.id / args.outDirName / "filter"
    if args.knownPath is None:
        args.knownPath = args.certPath / args.id / "known"
    if args.revokedPath is None:
        args.revokedPath = args.certPath / args.id / "revoked"
    args.diffPath = args.certPath / args.id / args.outDirName / "filter.stash"
    args.revokedKeys = args.certPath / args.id / args.outDirName / "list-revoked.keys"
    args.validKeys = args.certPath / args.id / args.outDirName / "list-valid.keys"
    return args


def saveStats(args, stats):
    statsPath = args.certPath / args.id / args.outDirName / "stats.json"
    os.makedirs(os.path.dirname(statsPath), exist_ok=True)
    with open(statsPath, "w") as f:
        f.write(json.dumps(stats))


@metrics.timer("Main")
def main():
    args = parseArgs(sys.argv[1:])
    log.debug(f"certs_to_crlite called with arguments: {args}")
    log.info(
        f"StatsD information submitting to {metrics._addr} with prefix {metrics._prefix}."
    )

    stats = {}
    known_nonrevoked_certs_len = None

    if args.onlyUseCache is False:
        log.info("Constructing known revoked and nonrevoked cert sets")
        results = createCertLists(
            known_path=args.knownPath,
            revoked_path=args.revokedPath,
            known_revoked_path=args.revokedKeys,
            known_nonrevoked_path=args.validKeys,
            exclude_issuer=args.excludeIssuer,
            stats=stats,
        )
        known_nonrevoked_certs_len = results["known_nonrevoked_certs_len"]

    # Setup for diff if previous filter specified
    if args.previd is not None:
        prior_folder = Path(args.certPath) / Path(args.previd)
        prior_revoked_path = prior_folder / Path("list-revoked.keys")
        if not prior_revoked_path.is_file():
            log.warning("Diff: Previous ID specified but no filter files found.")
        else:
            try:
                log.info("Diff: Making diff for known revoked entries")
                with open(prior_revoked_path, "rb") as prior_fp, open(
                    args.revokedKeys, "rb"
                ) as fp:
                    revoked_diff_by_issuer = find_additions(
                        old_by_issuer=crlite.readFromCertListByIssuer(prior_fp),
                        new_by_issuer=crlite.readFromCertListByIssuer(fp),
                    )

                log.info("Diff: Saving difference stash.")
                with metrics.timer("SaveAdditions"):
                    crlite.save_additions(
                        out_path=args.diffPath,
                        revoked_by_issuer=revoked_diff_by_issuer,
                    )
                log.info(
                    f"Difference stash complete. sz={Path(args.diffPath).stat().st_size} "
                    + f"memory={psutil.virtual_memory()}"
                )
                stats["stash_filesize"] = Path(args.diffPath).stat().st_size
                stats["stash_num_issuers"] = len(revoked_diff_by_issuer)
            except Exception as e:
                log.error(
                    f"Diff: Failed to make a diff, proceeding without one: {e}",
                    exc_info=sys.exc_info(),
                )

    if not known_nonrevoked_certs_len:
        log.info("known_nonrevoked_certs_len not calculated, calculating...")
        with metrics.timer("CalculateKnownNonrevokedCertsLen"):
            with open(args.validKeys, "rb") as fp:
                known_nonrevoked_certs_len = len(list(crlite.readFromCertList(fp)))

    log.info("revoked_certs loading...")
    with metrics.timer("LoadRevokedCerts"):
        with open(args.revokedKeys, "rb") as fp:
            revoked_certs = set(crlite.readFromCertList(fp))
    num_revoked_certs = len(revoked_certs)

    log.info(
        f"Ready to produce MLBF, counts are R: {num_revoked_certs} "
        + f"NR: {known_nonrevoked_certs_len}"
    )

    if num_revoked_certs == 0:
        sys.exit(1)

    # Generate new filter
    log.info("Constructing MLBF")
    with open(args.validKeys, "rb") as fp:
        mlbf = generateMLBF(
            args,
            stats,
            revoked_certs=revoked_certs,
            nonrevoked_certs=crlite.readFromCertList(fp),
            nonrevoked_certs_len=known_nonrevoked_certs_len,
        )

    log.info(f"MLBF complete. memory={psutil.virtual_memory()}")

    if mlbf.bitCount() > 0:
        log.info(f"Validating MLBF. Bit-count={mlbf.bitCount()}")
        with open(args.validKeys, "rb") as fp:
            verifyMLBF(
                args,
                mlbf,
                revoked_certs=revoked_certs,
                nonrevoked_certs=crlite.readFromCertList(fp),
            )

        log.info(f"MLBF validation complete. memory={psutil.virtual_memory()}")

        log.info("Saving MLBF.")
        saveMLBF(args, stats, mlbf)
        log.info(f"MLBF save complete. sz={Path(args.outFile).stat().st_size}")

    saveStats(args, stats)


if __name__ == "__main__":
    main()
