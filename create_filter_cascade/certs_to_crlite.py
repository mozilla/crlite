# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import base64
import bsdiff4
import json
import logging
import os
import stopwatch
import sys
from filtercascade import FilterCascade

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


def genCertLists(args, *, revoked_certs, nonrevoked_certs):
    counts = {}
    counts['knownrevoked'] = 0
    counts['knownnotrevoked'] = 0
    counts['crls'] = 0
    counts['nocrl'] = 0
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
            # Get known serials for the issuer
            knownpath = os.path.join(path, filename)
            knownlist = getCertList(knownpath, issuer)
            # Get revoked serials for issuer, if any
            revokedpath = os.path.join(args.revokedPath, "%s.known" % issuer)
            revlist = getCertList(revokedpath, issuer)
            if knownlist is None or revlist is None:
                # Skip issuer. No revocations for this issuer.  Not even empty list.
                counts['nocrl'] = counts['nocrl'] + 1
                continue
            knownSet = set(knownlist)
            revSet = set(revlist)
            knownRevSet = knownSet & revSet
            processedIssuers.add(issuer)
            counts['crls'] = counts['crls'] + len(revlist)
            counts['knownrevoked'] = counts['knownrevoked'] + len(knownRevSet)
            revoked_certs.extend(knownRevSet)
            # Decide if know serial is revoked or valid
            for key in knownSet:
                if key not in revSet:
                    nonrevoked_certs.append(key)
                    counts['knownnotrevoked'] = counts['knownnotrevoked'] + 1

    # Go through revoked issuers and process any that were not part of known issuers
    for path, dirs, files in os.walk(args.revokedPath):
        for filename in files:
            issuer = os.path.splitext(filename)[0]
            if issuer in args.excludeIssuer:
                continue
            if issuer not in processedIssuers:
                revokedpath = os.path.join(path, filename)
                revlist = getCertList(revokedpath, issuer)
                if revlist is None:
                    # Skip issuer. No revocations for this issuer.  Not even empty list.
                    counts['nocrl'] = counts['nocrl'] + 1
                else:
                    log.debug("Only revoked certs for Issuer {}".format(issuer))
                    counts['crls'] = counts['crls'] + len(revlist)
                    revoked_certs.extend(revlist)
    log.debug("CRL Revocations: %d KNR: %d KR: %d Issuers w/ no CRLs: %d" %
              (counts['crls'], counts['knownnotrevoked'],
               counts['knownrevoked'], counts['nocrl']))


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


def generateMLBF(args, *, revoked_certs, nonrevoked_certs):
    sw.start('mlbf')
    if args.diffMetaFile is not None:
        log.info(
            "Generating filter with characteristics from mlbf base file {}".
            format(args.diffMetaFile))
        mlbf_meta_file = open(args.diffMetaFile, 'rb')
        cascade = FilterCascade.loadDiffMeta(mlbf_meta_file)
        cascade.error_rates = args.errorrate
    else:
        log.info("Generating filter")
        cascade = FilterCascade.cascade_with_characteristics(
            int(len(revoked_certs) * args.capacity), args.errorrate)

    cascade.version = 1
    cascade.initialize(include=revoked_certs, exclude=nonrevoked_certs)

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


def saveMLBF(args, cascade):
    sw.start('save')
    os.makedirs(os.path.dirname(args.outFile), exist_ok=True)
    with open(args.outFile, 'wb') as mlbf_file:
        log.info("Writing to file {}".format(args.outFile))
        cascade.tofile(mlbf_file)
    with open(args.metaFile, 'wb') as mlbf_meta_file:
        log.info("Writing to meta file {}".format(args.metaFile))
        cascade.saveDiffMeta(mlbf_meta_file)
    if args.diffBaseFile is not None:
        log.info("Generating patch file {patch} from {base} to {out}".format(
            patch=args.patchFile, base=args.diffBaseFile, out=args.outFile))
        bsdiff4.file_diff(args.diffBaseFile, args.outFile, args.patchFile)
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
        "-knownPath",
        help="Directory containing known unexpired serials. Like ID/known/"
    )
    parser.add_argument(
        "-revokedPath",
        help="Directory containing known revoked serials, like ID/revoked/"
    )
    parser.add_argument(
        "-errorrate",
        type=float,
        nargs="*",
        default=[.02, .5],
        help="MLBF error rates.")
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
    args.outFile = os.path.join(args.certPath, args.id, "mlbf/filter")
    args.metaFile = os.path.join(args.certPath, args.id, "mlbf/filter.meta")
    if args.knownPath is None:
        args.knownPath = os.path.join(args.certPath, args.id, "known")
    if args.revokedPath is None:
        args.revokedPath = os.path.join(args.certPath, args.id, "revoked")
    args.revokedKeys = os.path.join(args.certPath, args.id,
                                    "mlbf/keys-revoked")
    args.validKeys = os.path.join(args.certPath, args.id, "mlbf/keys-valid")
    return args


def main():
    args = parseArgs(sys.argv[1:])
    log.debug(args)
    revoked_certs = []
    nonrevoked_certs = []

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
        diffMetaPath = os.path.join(args.certPath, args.previd, "mlbf",
                                    "filter.meta")
        diffBasePath = os.path.join(args.certPath, args.previd, "mlbf",
                                    "filter")
        if os.path.isfile(diffMetaPath) and os.path.isfile(diffBasePath):
            args.diffMetaFile = diffMetaPath
            args.diffBaseFile = diffBasePath
            args.patchFile = os.path.join(args.certPath, args.id, "mlbf",
                                          "filter.%s.patch" % args.previd)
        else:
            log.warning("Previous ID specified but no filter files found.")
    # Generate new filter
    mlbf = generateMLBF(
        args, revoked_certs=revoked_certs, nonrevoked_certs=nonrevoked_certs)
    if mlbf.bitCount() > 0:
        verifyMLBF(
            args,
            mlbf,
            revoked_certs=revoked_certs,
            nonrevoked_certs=nonrevoked_certs)
        saveMLBF(args, mlbf)
    sw.end('crlite')
    log.info(sw.format_last_report())


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    log = logging.getLogger('cert_to_crlite')
    main()
