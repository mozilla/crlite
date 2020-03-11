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
import psutil
import stopwatch
import sys
import struct
from filtercascade import FilterCascade
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
log = logging.getLogger('cert_to_crlite')

issuerCache = {}


def getIssuerIdFromCache(issuerSpkiHash):
    if not isinstance(issuerSpkiHash, bytes):
        raise Exception("issuerSpkiHash must be bytes")

    if issuerSpkiHash not in issuerCache:
        issuerCache[issuerSpkiHash] = IssuerId(issuerSpkiHash)

    return issuerCache[issuerSpkiHash]


class IssuerId(object):
    def __init__(self, issuerSpkiHash):
        if not isinstance(issuerSpkiHash, bytes):
            raise Exception("issuerSpkiHash must be bytes")

        self.issuerSpkiHash = issuerSpkiHash

    def to_bytes(self):
        return self.issuerSpkiHash

    def __repr__(self):
        return f"IssuerId({self.issuerSpkiHash.hex()})"

    def __hash__(self):
        return hash((self.issuerSpkiHash))

    def __eq__(self, other):
        return self.issuerSpkiHash == other.issuerSpkiHash


class CertId(object):
    def __init__(self, issuerId, serial):
        if not isinstance(issuerId, IssuerId):
            raise Exception("issuerId must be IssuerId")

        if not isinstance(serial, bytes):
            raise Exception("serial must be bytes")

        self.issuerId = issuerId
        self.serial = serial

    def to_bytes(self):
        return self.issuerId.to_bytes() + self.serial

    def __repr__(self):
        return f"CertID({self.issuerId.to_bytes().hex()}-{self.serial.hex()})"

    def __hash__(self):
        return hash((self.issuerId, self.serial))

    def __eq__(self, other):
        return self.issuerId == other.issuerId and self.serial == other.serial


def getCertList(certpath, issuer):
    issuerId = getIssuerIdFromCache(base64.urlsafe_b64decode(issuer))

    certlist = set()
    if not os.path.isfile(certpath):
        raise Exception(f"getCertList: {certpath} not a file")

    log.info(f"getCertList opening {Path(certpath)} (sz={Path(certpath).stat().st_size})")

    with open(certpath, "r") as f:
        try:
            for cnt, sHex in enumerate(f):
                try:
                    serial = bytes.fromhex(sHex)
                    certlist.add(CertId(issuerId, serial))
                except TypeError as te:
                    log.error(f"Couldn't decode line={cnt} issuer={issuer} serial "
                              + f"hex={sHex} because {te}")
        except Exception as e:
            log.debug(f"getCertList exception caught: {e}")
            log.error(f"Failed to load certs for {issuer} from {certpath}")
            breakpoint()
    return certlist


def initIssuerStats(stats, issuer):
    stats['Issuers'][issuer] = {
        'known': 0,
        'revoked': 0,
        'knownnotrevoked': 0,
        'knownrevoked': 0,
        'crl': False
    }


def genCertLists(args, stats, *, revoked_certs_by_issuer, nonrevoked_certs_by_issuer):
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
            log.info(f"genCertLists Processing issuer {issuer}, memory={psutil.virtual_memory()}")
            issuer_bytes = bytes(issuer, encoding="utf-8")

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
            revokedpath = os.path.join(args.revokedPath, issuer)
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
            if issuer_bytes not in revoked_certs_by_issuer:
                revoked_certs_by_issuer[issuer_bytes] = set()
            revoked_certs_by_issuer[issuer_bytes].update(knownRevoked)

            if issuer_bytes not in nonrevoked_certs_by_issuer:
                nonrevoked_certs_by_issuer[issuer_bytes] = set()
            nonrevoked_certs_by_issuer[issuer_bytes].update(knownNotRevoked)

            log.debug(f"getCertLists, file={filename} KNR={len(knownNotRevoked)} "
                      + f"KR={len(knownRevoked)}")

    log.info(f"Collected revoked_certs_by_issuer and nonrevoked_certs_by_issuer")

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


# bytes 0-3: N, number of serials as an unsigned long
# bytes 4-5: L, length of issuer field as a unsigned short
# bytes 6+: hash of issuer subject public key info of length L
# then N serials_structs
issuers_struct = struct.Struct(b'<LH')

# bytes 0-1: length of serial field as an unsigned short
# bytes 2+: serial number
serials_struct = struct.Struct(b'<H')

# bytes 0-3: N, number of revoked serials as an unsigned long
# bytes 4-7: M, number of nonrevoked serials as an unsigned long
# bytes 8-9: L, length of issuer field as a unsigned short
# bytes 10+: hash of issuer subject public key info of length L
# then N serials_structs followed by M serials_structs
additions_struct = struct.Struct(b'<LLH')


def writeSerials(file, serial_list):
    for k in serial_list:
        n = len(k.serial)
        if n > 0xFFFF:
            raise Exception("serial bytes > unsigned short")
        file.write(serials_struct.pack(n))
        file.write(k.serial)


def writeCertListByIssuer(file, certs_by_issuer):
    for issuer_base64 in certs_by_issuer:
        serial_list = certs_by_issuer[issuer_base64]
        num_serial_list = len(serial_list)

        issuer = base64.urlsafe_b64decode(issuer_base64)
        issuer_len = len(issuer)

        if num_serial_list > 0xFFFFFFFF:
            raise Exception("serial list length > unsigned long")
        if issuer_len > 0xFFFF:
            raise Exception("issuer bytes > unsigned short")

        file.write(issuers_struct.pack(num_serial_list, issuer_len))
        file.write(issuer)

        writeSerials(file, serial_list)


def save_additions(*, out_path, revoked_by_issuer, nonrevoked_by_issuer):
    with open(out_path, "wb") as file:
        all_issuers = set(revoked_by_issuer.keys()) | set(nonrevoked_by_issuer.keys())
        for issuer_b64 in all_issuers:
            issuer = base64.urlsafe_b64decode(issuer_b64)
            issuer_len = len(issuer)
            if issuer_len > 0xFFFF:
                raise Exception("issuer bytes > unsigned short")

            issuer_revocations = []
            if issuer_b64 in revoked_by_issuer:
                issuer_revocations = revoked_by_issuer[issuer_b64]
            num_issuer_revocations = len(issuer_revocations)
            if num_issuer_revocations > 0xFFFFFFFF:
                raise Exception("revocation list length > unsigned long")

            issuer_valid = []
            if issuer_b64 in nonrevoked_by_issuer:
                issuer_valid = nonrevoked_by_issuer[issuer_b64]
            num_issuer_valid = len(issuer_valid)
            if num_issuer_valid > 0xFFFFFFFF:
                raise Exception("valid list length > unsigned long")

            file.write(additions_struct.pack(
                num_issuer_revocations, num_issuer_valid, issuer_len
            ))
            file.write(issuer)

            writeSerials(file, issuer_revocations)
            writeSerials(file, issuer_valid)


class EOFException(Exception):
    pass


def expectRead(file, expectedBytes):
    data = []
    remaining = expectedBytes
    while remaining > 0:
        result = file.read(remaining)
        if len(result) == 0:
            raise EOFException()
        remaining -= len(result)
        data.extend(result)
    return result


def readCertListByIssuer(file, certs_by_issuer):
    try:
        while True:
            (num_serial_list, issuer_len) = issuers_struct.unpack(
                                                expectRead(file, issuers_struct.size))
            issuer_bytes = expectRead(file, issuer_len)

            issuerId = getIssuerIdFromCache(issuer_bytes)

            issuer = base64.urlsafe_b64encode(issuer_bytes)
            if issuer not in certs_by_issuer:
                certs_by_issuer[issuer] = set()

            for serial_idx in range(num_serial_list):
                (serial_len,) = serials_struct.unpack(expectRead(file, serials_struct.size))
                serial_bytes = expectRead(file, serial_len)

                certs_by_issuer[issuer].add(CertId(issuerId, serial_bytes))
    except EOFException:
        pass
    return


def saveCertLists(*, revoked_path, nonrevoked_path, revoked_certs_by_issuer,
                  nonrevoked_certs_by_issuer):
    log.info(f"Saving revoked/nonrevoked list {revoked_path} {nonrevoked_path}")
    os.makedirs(os.path.dirname(revoked_path), exist_ok=True)
    os.makedirs(os.path.dirname(nonrevoked_path), exist_ok=True)
    with open(revoked_path, 'wb') as revfile:
        writeCertListByIssuer(revfile, revoked_certs_by_issuer)
    with open(nonrevoked_path, 'wb') as nonrevfile:
        writeCertListByIssuer(nonrevfile, nonrevoked_certs_by_issuer)


def loadCertLists(*, revoked_path, nonrevoked_path, revoked_certs_by_issuer,
                  nonrevoked_certs_by_issuer):
    log.info(f"Loading revoked/nonrevoked list {revoked_path} {nonrevoked_path}")
    nonrevoked_certs_by_issuer.clear()
    revoked_certs_by_issuer.clear()
    with open(revoked_path, 'rb') as file:
        readCertListByIssuer(file, revoked_certs_by_issuer)
    with open(nonrevoked_path, 'rb') as file:
        readCertListByIssuer(file, nonrevoked_certs_by_issuer)


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


def find_additions(*, old_by_issuer, new_by_issuer):
    added = {}
    for issuer_b64 in new_by_issuer:
        n_set = set(new_by_issuer[issuer_b64])

        if issuer_b64 in old_by_issuer:
            o_set = set(old_by_issuer[issuer_b64])
            diff_set = n_set - o_set
            if diff_set:
                added[issuer_b64] = diff_set
        elif n_set:
            added[issuer_b64] = new_by_issuer[issuer_b64]

    return added


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
        help="Load revoked/non-revoked sorted certs from cache files.",
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
    args.diffPath = os.path.join(args.certPath, args.id, args.outDirName, "filter.stash")
    args.revokedKeys = os.path.join(args.certPath, args.id,
                                    args.outDirName, "list-revoked.keys")
    args.validKeys = os.path.join(args.certPath, args.id, args.outDirName, "list-valid.keys")
    return args


def saveStats(args, stats):
    statsPath = os.path.join(args.certPath, args.id, args.outDirName, "stats.json")
    os.makedirs(os.path.dirname(statsPath), exist_ok=True)
    with open(statsPath, 'w') as f:
        f.write(json.dumps(stats))


def main():
    args = parseArgs(sys.argv[1:])
    log = logging.getLogger('cert_to_crlite')
    log.debug(args)
    revoked_certs_by_issuer = {}
    nonrevoked_certs_by_issuer = {}

    stats = {}

    sw.start('crlite')
    if args.cacheKeys is True:
        if not (os.path.isfile(args.revokedKeys) and os.path.isfile(args.validKeys)):
            raise Exception(f"Could not load cacheKeys from {args.revokedKeys}"
                            + f" or {args.validKeys}")
        sw.start('load certs')

        loadCertLists(
            revoked_path=args.revokedKeys,
            nonrevoked_path=args.validKeys,
            revoked_certs_by_issuer=revoked_certs_by_issuer,
            nonrevoked_certs_by_issuer=nonrevoked_certs_by_issuer)
        sw.end('load certs')
    else:
        sw.start('certs')
        sw.start('gen certs')
        genCertLists(
            args,
            stats,
            revoked_certs_by_issuer=revoked_certs_by_issuer,
            nonrevoked_certs_by_issuer=nonrevoked_certs_by_issuer)
        sw.end('gen certs')
        sw.start('save certs')
        saveCertLists(
            revoked_path=args.revokedKeys,
            nonrevoked_path=args.validKeys,
            revoked_certs_by_issuer=revoked_certs_by_issuer,
            nonrevoked_certs_by_issuer=nonrevoked_certs_by_issuer)
        sw.end('save certs')
        sw.end('certs')

    # Setup for diff if previous filter specified
    if args.previd is not None:
        diff_revoked_path = os.path.join(args.certPath, args.previd, "list-revoked.keys")
        diff_valid_path = os.path.join(args.certPath, args.previd, "list-valid.keys")
        if not (os.path.isfile(diff_revoked_path) and os.path.isfile(diff_valid_path)):
            log.warning("Previous ID specified but no filter files found.")
        else:
            sw.start('load previous filter')
            prior_revoked_certs_by_issuer = {}
            prior_nonrevoked_certs_by_issuer = {}

            loadCertLists(
                revoked_path=diff_revoked_path,
                nonrevoked_path=diff_valid_path,
                revoked_certs_by_issuer=prior_revoked_certs_by_issuer,
                nonrevoked_certs_by_issuer=prior_nonrevoked_certs_by_issuer)
            sw.end('load previous filter')

            sw.start('make diff')
            revoked_diff_by_isssuer = find_additions(
                old_by_issuer=prior_revoked_certs_by_issuer,
                new_by_issuer=revoked_certs_by_issuer)
            nonrevoked_diff_by_issuer = find_additions(
                old_by_issuer=prior_nonrevoked_certs_by_issuer,
                new_by_issuer=nonrevoked_certs_by_issuer)

            save_additions(
                out_path=args.diffPath,
                revoked_by_issuer=revoked_diff_by_isssuer,
                nonrevoked_by_issuer=nonrevoked_diff_by_issuer)
            sw.end('make diff')

    revoked_certs = []
    [revoked_certs.extend(d) for d in revoked_certs_by_issuer.values()]
    revoked_certs_by_issuer = {}  # allow garbage collection

    nonrevoked_certs = []
    [nonrevoked_certs.extend(d) for d in nonrevoked_certs_by_issuer.values()]
    nonrevoked_certs_by_issuer = {}  # allow garbage collection

    num_revoked_certs = len(revoked_certs)
    num_nonrevoked_certs = len(nonrevoked_certs)

    log.debug(f"Cert lists revoked/non-revoked R: {num_revoked_certs} "
              + f"NR: {num_nonrevoked_certs}")

    if num_revoked_certs == 0 and num_nonrevoked_certs == 0:
        log.info("No certificates, exiting failure")
        sys.exit(1)

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
    main()
