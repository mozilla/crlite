# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Python Standard Library
from datetime import datetime
import json
import OpenSSL
import os
import sys
import argparse
import bsdiff4
import logging
import stopwatch

# Local modules
from FilterCascade import FilterCascade

sw = stopwatch.StopWatch()


def getCertList(certpath, aki):
    certlist = None
    if os.path.isfile(certpath):
        with open(certpath, "r") as f:
            try:
                serials = json.load(f)
                certlist = set()
                for s in serials:
                    certlist.add(aki + str(s))
            except Exception as e:
                log.debug("{}".format(e))
                log.error("Failed to load certs for {} from {}".format(
                    aki, certpath))
    return certlist


def genCertLists(args, *, revoked_certs, nonrevoked_certs):
    counts = {}
    counts['knownrevoked'] = 0
    counts['knownnotrevoked'] = 0
    counts['crls'] = 0
    counts['nocrl'] = 0
    log.info("Generating revoked/nonrevoked list {known} {revoked}".format(
        known=args.knownPath, revoked=args.revokedPath))

    processedAKIs = set()
    # Go through known AKIs/serials
    # generate a revoked/nonrevoked master list
    for path, dirs, files in os.walk(args.knownPath):
        for filename in files:
            aki = os.path.splitext(filename)[0]
            if aki in args.excludeaki:
                continue
            # Get known serials for AKI
            knownpath = os.path.join(path, filename)
            knownlist = getCertList(knownpath, aki)
            # Get revoked serials for AKI, if any
            revokedpath = os.path.join(args.revokedPath, "%s.revoked" % aki)
            revlist = getCertList(revokedpath, aki)
            if knownlist == None or revlist == None:
                # Skip AKI. No revocations for this AKI.  Not even empty list.
                counts['nocrl'] = counts['nocrl'] + 1
                continue
            processedAKIs.add(aki)
            counts['crls'] = counts['crls'] + len(revlist)
            revoked_certs.extend(revlist)
            # Decide if know serial is revoked or valid
            for key in knownlist:
                if key not in revlist:
                    nonrevoked_certs.append(key)
                    counts['knownnotrevoked'] = counts['knownnotrevoked'] + 1
                else:
                    # The revoked keys were already processed above.
                    # Just count it here.
                    counts['knownrevoked'] = counts['knownrevoked'] + 1

    # Go through revoked AKIs and process any that were not part of known AKIs
    for path, dirs, files in os.walk(args.revokedPath):
        for filename in files:
            aki = os.path.splitext(filename)[0]
            if aki in args.excludeaki:
                continue
            if aki not in processedAKIs:
                revokedpath = os.path.join(path, filename)
                revlist = getCertList(revokedpath, aki)
                if revlist == None:
                    # Skip AKI. No revocations for this AKI.  Not even empty list.
                    counts['nocrl'] = counts['nocrl'] + 1
                else:
                    log.debug("Only revoked certs for AKI {}".format(aki))
                    counts['crls'] = counts['crls'] + len(revlist)
                    revoked_certs.extend(revlist)
    log.debug("R: %d KNR: %d KR: %d NOCRL: %d" %
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
            revfile.write("%s\n" % k)
        for k in nonrevoked_certs:
            nonrevfile.write("%s\n" % k)


def loadCertLists(args, *, revoked_certs, nonrevoked_certs):
    log.info("Loading revoked/nonrevoked list {revoked} {valid}".format(
        revoked=args.revokedKeys, valid=args.validKeys))
    nonrevoked_certs.clear()
    revoked_certs.clear()
    with open(args.revokedKeys, 'r') as file:
        for line in file:
            revoked_certs.append(line[:-1])
    with open(args.validKeys, 'r') as file:
        for line in file:
            nonrevoked_certs.append(line[:-1])


def generateMLBF(args, *, revoked_certs, nonrevoked_certs):
    sw.start('mlbf')
    if args.diffMetaFile != None:
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

    cascade.initialize(include=revoked_certs, exclude=nonrevoked_certs)

    log.debug("Filter cascade layers: {layers}, bit: {bits}".format(
        layers=cascade.layerCount(), bits=cascade.bitCount()))
    sw.end('mlbf')
    return cascade


def verifyMLBF(args, cascade, *, revoked_certs, nonrevoked_certs):
    # Verify generate filter
    sw.start('verify')
    if args.noVerify == False:
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
    if args.diffBaseFile != None:
        log.info("Genderating patch file {patch} from {base} to {out}".format(
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
        help=
        "Directory containing known unexpired serials.  <AKI>.known JSON files."
    )
    parser.add_argument(
        "-revokedPath",
        help=
        "Directory containing known unexpired serials.  <AKI>.known JSON files."
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
        "-excludeaki",
        nargs="*",
        default=[],
        help="Exclude the specified AKIs")
    parser.add_argument(
        "-cachekeys",
        help=
        "Save revoked/non-revoked sorted certs to file or load from file if it exists.",
        action="store_true")
    parser.add_argument(
        "-noVerify", help="Skip MLBF verification", action="store_true")
    args = parser.parse_args(argv)
    args.diffMetaFile = None
    args.diffBaseFile = None
    args.patchFile = None
    args.outFile = os.path.join(args.certPath, args.id, "mlbf/filter")
    args.metaFile = os.path.join(args.certPath, args.id, "mlbf/filter.meta")
    if args.knownPath == None:
        args.knownPath = os.path.join(args.certPath, args.id, "known")
    if args.revokedPath == None:
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

    marktime = datetime.utcnow()
    sw.start('crlite')
    sw.start('certs')
    if args.cachekeys == True and os.path.isfile(
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
        if args.cachekeys == True:
            saveCertLists(
                args,
                revoked_certs=revoked_certs,
                nonrevoked_certs=nonrevoked_certs)
    log.debug(
        "Cert lists revoked/non-revoked R: {revoked} NR: {nonrevoked}".format(
            revoked=len(revoked_certs), nonrevoked=len(nonrevoked_certs)))
    sw.end('certs')

    # Setup for diff if previous filter specified
    if args.previd != None:
        # The previous filter didn't have a diff, use the base
        args.diffMetaFile = os.path.join(args.certPath, args.previd, "mlbf",
                                         "filter.meta")
        args.diffBaseFile = os.path.join(args.certPath, args.previd, "mlbf",
                                         "filter")
        args.patchFile = os.path.join(args.certPath, args.id, "mlbf",
                                      "filter.%s.patch" % args.previd)
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
