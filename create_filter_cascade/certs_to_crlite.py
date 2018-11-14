# Python Standard Library
from datetime import datetime
import json
import OpenSSL
import os
import sys
import argparse
import logging

# Local modules
from FilterCascade import FilterCascade

times = dict()


def open_crl(rawtext):
    try:
        return OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, rawtext)
    except:
        pass
    try:
        return OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM, rawtext)
    except:
        return False


def getRevokedCRLCerts(crlbase):
    count = 0
    marktime = datetime.utcnow()
    totalelapsed = 0
    revoked_set = set()
    for path, dirs, files in os.walk(crlbase):
        for filename in files:
            crlpath = os.path.join(path, filename)
            aki = os.path.basename(os.path.dirname(crlpath))
            with open(crlpath, "rb") as crlfile:
                rawdata = crlfile.read()
                crl = open_crl(rawdata)
                if crl != False:
                    revoked = crl.get_revoked()
                    if revoked != None:
                        for rvk in revoked:
                            revoked_set.add(
                                aki + str(rvk.get_serial().decode('utf-8')))
                            count = count + 1
                            elapsedinterval = datetime.utcnow() - marktime
                            if elapsedinterval.total_seconds() > 15:
                                totalelapsed += elapsedinterval.total_seconds()
                                log.debug("Time %d R: %d " % (totalelapsed, count))
                                marktime = datetime.utcnow()
    return revoked_set


def getRevokedCerts(args, aki):
    revoked_set = set()
    revokedpath = "%s/%s.revoked" % (args.revokedPath, aki)
    if os.path.isfile(revokedpath):
        with open(revokedpath, "r") as f:
            try:
                serials = json.load(f)
            except Exception as e:
                log.debug("%s" % e)
                log.error("Failed %s %s" % (aki, revokedpath))
            for s in serials:
                revoked_set.add(aki + str(s))
    return revoked_set


def genCertLists(args, revoked_certs, nonrevoked_certs):
    marktime = datetime.utcnow()
    totalelapsed = 0
    counts = {}
    counts['knownrevoked'] = 0
    counts['knownnotrevoked'] = 0
    counts['crls'] = 0
    if args.regen == False and os.path.isfile(
            args.revokedKeys) and os.path.isfile(args.validKeys):
        return False
    if not os.path.exists(args.knownPath) or not os.path.exists(
            args.revokedPath):
        log.error("path for known or revoked certs doesn't exist")
        sys.exit()
    log.info("Generating revoked/nonrevoked list %s %s %s %s" %
          (args.knownPath, args.revokedPath, args.revokedKeys, args.validKeys))
    os.makedirs(os.path.dirname(args.revokedKeys), exist_ok=True)
    os.makedirs(os.path.dirname(args.revokedKeys), exist_ok=True)
    with open(args.revokedKeys, 'w') as revfile, open(args.validKeys,
                                                      'w') as nonrevfile:
        knownAKIs = set()
        # Go through known AKIs/serials
        # generate a revoked/no
        for path, dirs, files in os.walk(args.knownPath):
            for filename in files:
                aki = os.path.splitext(filename)[0]
                if aki in args.excludeaki:
                    continue
                knownAKIs.add(aki)
                knownpath = os.path.join(path, filename)
                # Get known serials for AKI
                with open(knownpath, "r") as f:
                    try:
                        serials = json.load(f)
                    except Exception as e:
                        log.error("%s" % e)
                        log.error("Failed %s %s" % (aki, knownpath))
                    # Get revoked serials for AKI, if any
                    revlist = getRevokedCerts(args, aki)
                    counts['crls'] = counts['crls'] + len(revlist)
                    revoked_certs.extend(revlist)
                    for r in revlist:
                        revfile.write(r + "\n")
                    # Decide if know serial is revoked or valid
                    for s in serials:
                        key = aki + str(s)
                        elapsedinterval = datetime.utcnow() - marktime
                        if key not in revlist:
                            nonrevoked_certs.append(key)
                            nonrevfile.write(key + "\n")
                            counts['knownnotrevoked'] = counts[
                                'knownnotrevoked'] + 1
                        else:
                            # The revoked keys were already processed above.
                            # Just count it here.
                            counts['knownrevoked'] = counts['knownrevoked'] + 1
                        if elapsedinterval.total_seconds() > 15:
                            totalelapsed += elapsedinterval.total_seconds()
                            log.debug("Time %d R: %d KNR: %d KR: %d" %
                                  (totalelapsed, counts['crls'],
                                   counts['knownnotrevoked'],
                                   counts['knownrevoked']))
                            marktime = datetime.utcnow()

        # Go through revoked AKIs and process any that were not part of known AKIs
        for path, dirs, files in os.walk(args.revokedPath):
            for filename in files:
                aki = os.path.splitext(filename)[0]
                if aki in args.excludeaki:
                    continue
                if aki not in knownAKIs:
                    log.debug("Only revoked certs for AKI %s" % aki)
                    revlist = getRevokedCerts(args, aki)
                    counts['crls'] = counts['crls'] + len(revlist)
                    revoked_certs.extend(revlist)
                    for r in revlist:
                        revfile.write(r + "\n")
    log.debug("Time %d R: %d KNR: %d KR: %d" %
          (totalelapsed, counts['crls'], counts['knownnotrevoked'],
           counts['knownrevoked']))
    return True


def loadCertLists(args, revoked_certs, nonrevoked_certs):
    log.info("Loading revoked/nonrevoked list %s %s" % (args.revokedKeys,
                                                     args.validKeys))
    nonrevoked_certs.clear()
    revoked_certs.clear()
    with open(args.revokedKeys, 'r') as file:
        for line in file:
            revoked_certs.append(line[:-1])
    with open(args.validKeys, 'r') as file:
        for line in file:
            nonrevoked_certs.append(line[:-1])


def generateMLBF(args, revoked_certs, nonrevoked_certs):
    marktime = datetime.utcnow()
    if args.diffMetaFile != None:
        log.info("Generating filter with characteristics from mlbf base file %s" %
              args.diffMetaFile)
        mlbf_meta_file = open(args.diffMetaFile, 'rb')
        cascade = FilterCascade.loadDiffMeta(mlbf_meta_file)
    else:
        log.info("Generating filter")
        cascade = FilterCascade.cascade_with_characteristics(
            int(len(revoked_certs) * 1.1), [0.02, 0.5])

    if args.limit != None:
        log.debug("Data set limited to %d revoked and %d non-revoked" %
              (args.limit, args.limit * 10))
        cascade.initialize(revoked_certs[:args.limit],
                           nonrevoked_certs[:args.limit * 10])
    else:
        cascade.initialize(revoked_certs, nonrevoked_certs)

    times['filtertime'] = datetime.utcnow() - marktime
    log.debug("Filter cascade time: %d, layers: %d, bit: %d" %
          (times['filtertime'].total_seconds(), cascade.layerCount(),
           cascade.bitCount()))

    # Verify generate filter
    marktime = datetime.utcnow()
    if args.noVerify == False:
        loadCertLists(args, revoked_certs, nonrevoked_certs)
        log.info("Checking/verifying certs against MLBF")
        if args.limit != None:
            cascade.check(revoked_certs[:args.limit],
                          nonrevoked_certs[:args.limit * 10])
        else:
            cascade.check(revoked_certs, nonrevoked_certs)
    times['checktime'] = datetime.utcnow() - marktime
    log.debug("Total check time %d seconds" % times['checktime'].total_seconds())
    return cascade


def saveMLBF(args, cascade):
    marktime = datetime.utcnow()
    log.info("Writing to file %s" % args.outFile)
    mlbf_file = open(args.outFile, 'wb')
    cascade.tofile(mlbf_file)
    log.info("Writing to meta file %s" % (args.metaFile))
    mlbf_meta_file = open(args.metaFile, 'wb')
    cascade.saveDiffMeta(mlbf_meta_file)
    times['savetime'] = datetime.utcnow() - marktime


def printStats():
    log.info("Total cert sort revoked/non-revoked time %d seconds" %
          times['certtime'].total_seconds())
    log.info("Total cascade filter time %d seconds" %
          times['filtertime'].total_seconds())
    log.info("Total check time %d seconds" % times['checktime'].total_seconds())
    log.info("Total write time %d seconds" % times['savetime'].total_seconds())
    log.info("Total time %d seconds" %
          (times['endtime'] - times['starttime']).total_seconds())


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
        "-limit",
        type=int,
        help="Only process specified revocations. Non-revoked will be 10x")
    parser.add_argument(
        "-errorrate", type=float, default=".5", help="MLBF error rate.")
    parser.add_argument(
        "-capacity", type=float, default="1.1", help="MLBF capacity.")
    parser.add_argument(
        "-excludeaki", nargs="*", help="Exclude the specified AKIs")
    parser.add_argument(
        "-regen",
        help="Regenerate revoked/non-revoked data",
        action="store_true")
    parser.add_argument(
        "-noVerify", help="Skip MLBF verification", action="store_true")
    args = parser.parse_args(argv)
    if args.previd != None:
        args.diffMetaFile = "%s/%s/mlbf/filter.meta" % (args.certPath,
                                                        args.previd)
    else:
        args.diffMetaFile = None
    if args.knownPath == None:
        args.knownPath = "%s/%s/known" % (args.certPath, args.id)
    if args.revokedPath == None:
        args.revokedPath = "%s/%s/revoked" % (args.certPath, args.id)
    if args.excludeaki == None:
        args.excludeaki = []
    args.revokedKeys = "%s/%s/mlbf/keys-revoked" % (args.certPath, args.id)
    args.validKeys = "%s/%s/mlbf/keys-valid" % (args.certPath, args.id)
    args.outFile = "%s/%s/mlbf/filter" % (args.certPath, args.id)
    args.metaFile = "%s/%s/mlbf/filter.meta" % (args.certPath, args.id)
    return args


def main():
    args = parseArgs(sys.argv[1:])
    log.debug(args)
    revoked_certs = []
    nonrevoked_certs = []

    marktime = datetime.utcnow()
    times['starttime'] = marktime
    if genCertLists(args, revoked_certs, nonrevoked_certs) == False:
        loadCertLists(args, revoked_certs, nonrevoked_certs)
    times['certtime'] = datetime.utcnow() - marktime
    log.debug("Cert sort revoked/non-revoked time: %d s R: %d NR: %d" %
          (times['certtime'].total_seconds(), len(revoked_certs),
           len(nonrevoked_certs)))

    mlbf = generateMLBF(args, revoked_certs, nonrevoked_certs)
    saveMLBF(args, mlbf)
    times['endtime'] = datetime.utcnow()
    printStats()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    log = logging.getLogger('cert_to_crlite')
    main()
