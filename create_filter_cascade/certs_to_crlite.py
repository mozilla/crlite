#!/usr/bin/env python3

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import base64
import bsdiff4
import json
import logging
import math
import os
import stopwatch
import sys
from filtercascade import FilterCascade

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
#   "mlbf_metafilesize"  : Int, Size of the MLBF metafile in bytes
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

sw = stopwatch.StopWatch()


def getCertList(certpath, issuer):
    certlist = None
    if os.path.isfile(certpath):
        with open(certpath, "r") as f:
            try:
                serials = json.load(f)
                certlist = set()
                for s in serials:
                    key = base64.urlsafe_b64decode(
                            issuer) + base64.urlsafe_b64decode(s)
                    certlist.add(key)
            except Exception as e:
                breakpoint()
                log.debug("{}".format(e))
                log.error("Failed to load certs for {} from {}".format(
                    issuer, certpath))
    return certlist


def initIssuerStats(stats, issuer):
    stats['Issuers'][issuer] = {
        'known': 0,
        'revoked': 0,
        'knownnotrevoked': 0,
        'knownrevoked': 0,
        'crl': False
    }


def genCertLists(args, stats, *, revoked_certs, nonrevoked_certs):
    stats['knownrevoked'] = 0
    stats['knownnotrevoked'] = 0
    stats['revoked'] = 0
    stats['known'] = 0
    stats['nocrl'] = 0
    stats['Issuers'] = {}
    log.info("Generating revoked/nonrevoked list {known} {revoked}".format(
        known=args.knownPath, revoked=args.revokedPath))

    processedIssuers = set()
    # Go through known issuers/serials
    # generate a revoked/nonrevoked master list
    for path, dirs, files in os.walk(args.knownPath):
        for filename in files:
            issuer = os.path.splitext(filename)[0]
            if issuer in args.excludeIssuer:
                continue

            initIssuerStats(stats, issuer)

            # Get known serials for the issuer
            knownpath = os.path.join(path, filename)
            knownlist = getCertList(knownpath, issuer)

            if knownlist:
                stats['known'] += len(knownlist)
            else:
                knownlist = set()
            stats['Issuers'][issuer]['known'] = len(knownlist)

            # Get revoked serials for issuer, if any
            revokedpath = os.path.join(args.revokedPath, "%s.known" % issuer)
            revlist = getCertList(revokedpath, issuer)

            if revlist:
                stats['revoked'] += len(revlist)
                stats['Issuers'][issuer]['crl'] = True
            else:
                stats['nocrl'] += 1
                revlist = set()
            stats['Issuers'][issuer]['revoked'] = len(revlist)

            processedIssuers.add(issuer)

            knownNotRevoked = knownlist - revlist
            knownRevoked = knownlist & revlist
            stats['knownnotrevoked'] += len(knownNotRevoked)
            stats['knownrevoked'] += len(knownRevoked)
            stats['Issuers'][issuer]['knownnotrevoked'] = len(knownNotRevoked)
            stats['Issuers'][issuer]['knownrevoked'] = len(knownRevoked)

            # cbw - Don't add all revocations, only add revocations
            # for known certificates. Revocations for unknown certs
            # are useless cruft
            revoked_certs.extend(knownRevoked)
            nonrevoked_certs.extend(knownNotRevoked)

    # Go through revoked issuers and process any that were not part of known issuers
    for path, dirs, files in os.walk(args.revokedPath):
        for filename in files:
            issuer = os.path.splitext(filename)[0]
            if issuer in args.excludeIssuer:
                continue
            if issuer not in processedIssuers:
                initIssuerStats(stats, issuer)

                revokedpath = os.path.join(path, filename)
                revlist = getCertList(revokedpath, issuer)
                if revlist is None:
                    # Skip issuer. No revocations for this issuer.  Not even empty list.
                    stats['nocrl'] += 1
                else:
                    log.debug("Only revoked certs for issuer {}".format(issuer))
                    stats['revoked'] += len(revlist)
                    stats['Issuers'][issuer]['crl'] = True
                    stats['Issuers'][issuer]['revoked'] = len(revlist)

    log.debug("R: %d K: %d KNR: %d KR: %d NOCRL: %d" %
              (stats['revoked'], stats['known'], stats['knownnotrevoked'],
               stats['knownrevoked'], stats['nocrl']))


def saveCertLists(args, *, revoked_certs, nonrevoked_certs):
    log.info("Saving revoked/nonrevoked list {revoked} {valid}".format(
        revoked=args.revokedKeys, valid=args.validKeys))
    os.makedirs(os.path.dirname(args.revokedKeys), exist_ok=True)
    os.makedirs(os.path.dirname(args.validKeys), exist_ok=True)
    with open(args.revokedKeys, 'w') as revfile, open(args.validKeys,
                                                      'w') as nonrevfile:
        for k in revoked_certs:
            revfile.write("%s\n" % base64.standard_b64encode(k).decode("utf-8"))
        for k in nonrevoked_certs:
            nonrevfile.write("%s\n" % base64.standard_b64encode(k).decode("utf-8"))


def loadCertLists(args, *, revoked_certs, nonrevoked_certs):
    log.info("Loading revoked/nonrevoked list {revoked} {valid}".format(
        revoked=args.revokedKeys, valid=args.validKeys))
    nonrevoked_certs.clear()
    revoked_certs.clear()
    with open(args.revokedKeys, 'r') as file:
        for line in file:
            revoked_certs.append(base64.standard_b64decode(line[:-1].encode("utf-8")))
    with open(args.validKeys, 'r') as file:
        for line in file:
            nonrevoked_certs.append(base64.standard_b64decode(line[:-1].encode("utf-8")))


def getFPRs(revoked_certs, nonrevoked_certs):
    return [len(revoked_certs) / (math.sqrt(2) * len(nonrevoked_certs)), 0.5]


def generateMLBF(args, stats, *, revoked_certs, nonrevoked_certs):
    sw.start('mlbf')
    fprs = getFPRs(revoked_certs, nonrevoked_certs)
    if args.diffMetaFile is not None:
        log.info(
            "Generating filter with characteristics from mlbf base file {}".
            format(args.diffMetaFile))
        mlbf_meta_file = open(args.diffMetaFile, 'rb')
        cascade = FilterCascade.loadDiffMeta(mlbf_meta_file)
        cascade.error_rates = fprs
    else:
        log.info("Generating filter")
        cascade = FilterCascade.cascade_with_characteristics(
            int(len(revoked_certs) * args.capacity),
            fprs)

    cascade.version = 1
    cascade.initialize(include=revoked_certs, exclude=nonrevoked_certs)

    stats['mlbf_fprs'] = fprs
    stats['mlbf_version'] = cascade.version
    stats['mlbf_layers'] = cascade.layerCount()
    stats['mlbf_bits'] = cascade.bitCount()

    log.debug("Filter cascade layers: {layers}, bit: {bits}".format(
        layers=cascade.layerCount(), bits=cascade.bitCount()))
    sw.end('mlbf')
    return cascade


def verifyMLBF(args, cascade, *, revoked_certs, nonrevoked_certs):
    # Verify generate filter
    sw.start('verify')
    if args.noVerify is False:
        log.info("Checking/verifying certs against MLBF")
        cascade.check(entries=revoked_certs, exclusions=nonrevoked_certs)
    sw.end('verify')


def saveMLBF(args, stats, cascade):
    sw.start('save')
    os.makedirs(os.path.dirname(args.outFile), exist_ok=True)
    with open(args.outFile, 'wb') as mlbf_file:
        log.info("Writing to file {}".format(args.outFile))
        cascade.tofile(mlbf_file)
    stats['mlbf_filesize'] = os.stat(args.outFile).st_size
    with open(args.metaFile, 'wb') as mlbf_meta_file:
        log.info("Writing to meta file {}".format(args.metaFile))
        cascade.saveDiffMeta(mlbf_meta_file)
    stats['mlbf_metafilesize'] = os.stat(args.metaFile).st_size
    if args.diffBaseFile is not None:
        log.info("Generating patch file {patch} from {base} to {out}".format(
            patch=args.patchFile, base=args.diffBaseFile, out=args.outFile))
        bsdiff4.file_diff(args.diffBaseFile, args.outFile, args.patchFile)
        stats['mlbf_diffsize'] = os.stat(args.patchFile).st_size
    sw.end('save')


def parseArgs(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("id", help="CT baseline identifier", metavar=('ID'))
    parser.add_argument(
        "-previd",
        help="Previous identifier to use for diff",
        metavar=('DIFFID'))
    parser.add_argument(
        "-certPath",
        help="Directory containing CT data.",
        default="/ct/processing")
    parser.add_argument(
        "-outDirName",
        help="Name of the directory to store output in. Default=mlbf/",
        default="mlbf")
    parser.add_argument(
        "-knownPath",
        help="Directory containing known unexpired serials. Like ID/known/"
    )
    parser.add_argument(
        "-revokedPath",
        help="Directory containing known revoked serials, like ID/revoked/"
    )
    parser.add_argument(
        "-capacity", type=float, default="1.1", help="MLBF capacity.")
    parser.add_argument(
        "-excludeIssuer",
        nargs="*",
        default=[],
        help="Exclude the specified Issuers")
    parser.add_argument(
        "-cacheKeys",
        help="Save revoked/non-revoked sorted certs to file or load from file if it exists.",
        action="store_true")
    parser.add_argument(
        "-noVerify", help="Skip MLBF verification", action="store_true")
    args = parser.parse_args(argv)
    args.diffMetaFile = None
    args.diffBaseFile = None
    args.patchFile = None
    args.outFile = os.path.join(args.certPath, args.id, args.outDirName, "filter")
    args.metaFile = os.path.join(args.certPath, args.id, args.outDirName, "filter.meta")
    if args.knownPath is None:
        args.knownPath = os.path.join(args.certPath, args.id, "known")
    if args.revokedPath is None:
        args.revokedPath = os.path.join(args.certPath, args.id, "revoked")
    args.revokedKeys = os.path.join(args.certPath, args.id,
                                    args.outDirName, "keys-revoked")
    args.validKeys = os.path.join(args.certPath, args.id, args.outDirName, "keys-valid")
    return args


def saveStats(args, stats):
    with open(os.path.join(args.certPath, args.id, args.outDirName, "stats.json"), 'w') as f:
        f.write(json.dumps(stats))


def main():
    args = parseArgs(sys.argv[1:])
    log.debug(args)
    revoked_certs = []
    nonrevoked_certs = []

    stats = {}

    sw.start('crlite')
    sw.start('certs')
    if args.cacheKeys is True and os.path.isfile(
            args.revokedKeys) and os.path.isfile(args.validKeys):
        loadCertLists(
            args,
            revoked_certs=revoked_certs,
            nonrevoked_certs=nonrevoked_certs)
    else:
        genCertLists(
            args,
            stats,
            revoked_certs=revoked_certs,
            nonrevoked_certs=nonrevoked_certs)
        if args.cacheKeys is True:
            saveCertLists(
                args,
                revoked_certs=revoked_certs,
                nonrevoked_certs=nonrevoked_certs)
    log.debug(
        "Cert lists revoked/non-revoked R: {revoked} NR: {nonrevoked}".format(
            revoked=len(revoked_certs), nonrevoked=len(nonrevoked_certs)))
    sw.end('certs')

    # Setup for diff if previous filter specified
    if args.previd is not None:
        diffMetaPath = os.path.join(args.certPath, args.previd, args.outDirName,
                                    "filter.meta")
        diffBasePath = os.path.join(args.certPath, args.previd, args.outDirName,
                                    "filter")
        if os.path.isfile(diffMetaPath) and os.path.isfile(diffBasePath):
            args.diffMetaFile = diffMetaPath
            args.diffBaseFile = diffBasePath
            args.patchFile = os.path.join(args.certPath, args.id, args.outDirName,
                                          "filter.%s.patch" % args.previd)
        else:
            log.warning("Previous ID specified but no filter files found.")
    # Generate new filter
    mlbf = generateMLBF(
        args, stats, revoked_certs=revoked_certs, nonrevoked_certs=nonrevoked_certs)
    if mlbf.bitCount() > 0:
        verifyMLBF(
            args,
            mlbf,
            revoked_certs=revoked_certs,
            nonrevoked_certs=nonrevoked_certs)
        saveMLBF(args, stats, mlbf)

    saveStats(args, stats)
    sw.end('crlite')
    log.info(sw.format_last_report())


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    log = logging.getLogger('cert_to_crlite')
    main()
