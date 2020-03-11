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

    def base64(self):
        return base64.urlsafe_b64encode(self.issuerSpkiHash)

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


class IssuerDataOnDisk(object):
    def __init__(self, *, issuer, knownPath, revokedPath):
        self.issuer = issuer
        self.knownPath = knownPath
        self.revokedPath = revokedPath

    def __repr__(self):
        return f"{self.issuer}"

    def load_and_make_sets(self, stats):
        knownSet = getCertList(self.knownPath, self.issuer)
        if knownSet:
            stats['known'] += len(knownSet)
        else:
            knownSet = set()
        stats['Issuers'][self.issuer]['known'] = len(knownSet)

        revSet = getCertList(self.revokedPath, self.issuer)
        if revSet:
            stats['revoked'] += len(revSet)
            stats['Issuers'][self.issuer]['crl'] = True
        else:
            stats['nocrl'] += 1
            revSet = set()
        stats['Issuers'][self.issuer]['revoked'] = len(revSet)

        knownNotRevoked = knownSet - revSet
        knownRevoked = knownSet & revSet
        return {
            "issuer": self.issuer,
            "knownNotRevoked": knownNotRevoked,
            "knownRevoked": knownRevoked,
        }


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


def genIssuerPathObjects(*, knownPath, revokedPath, excludeIssuer):
    for path, dirs, files in os.walk(knownPath):
        for filename in files:
            issuer = os.path.splitext(filename)[0]
            if issuer in excludeIssuer:
                continue

            yield IssuerDataOnDisk(issuer=issuer, knownPath=path / Path(filename),
                                   revokedPath=revokedPath / Path(issuer))


def createCertLists(*, known_path, revoked_path, known_revoked_path, known_nonrevoked_path,
                    exclude_issuer, stats):
    stats['knownrevoked'] = 0
    stats['knownnotrevoked'] = 0
    stats['revoked'] = 0
    stats['known'] = 0
    stats['nocrl'] = 0
    stats['Issuers'] = {}

    log.info(f"Generating revoked/nonrevoked lists {known_revoked_path} {known_nonrevoked_path} "
             + f"from {known_path} and {revoked_path}")

    os.makedirs(os.path.dirname(known_revoked_path), exist_ok=True)
    os.makedirs(os.path.dirname(known_nonrevoked_path), exist_ok=True)

    with open(known_revoked_path, 'wb') as revfile, open(known_nonrevoked_path,
                                                         'wb') as nonrevfile:
        issuerPathIter = genIssuerPathObjects(knownPath=known_path, revokedPath=revoked_path,
                                              excludeIssuer=exclude_issuer)
        for issuerObj in sorted(issuerPathIter, key=lambda i: i.issuer):
            log.info(f"createCertLists Processing issuerObj={issuerObj}, "
                     + f"memory={psutil.virtual_memory()}")

            issuer = issuerObj.issuer
            initIssuerStats(stats, issuer)

            sets = issuerObj.load_and_make_sets(stats)

            known_nonrevoked_certs_len = len(sets["knownNotRevoked"])
            known_revoked_certs_len = len(sets["knownRevoked"])

            stats['knownnotrevoked'] += known_nonrevoked_certs_len
            stats['knownrevoked'] += known_revoked_certs_len
            stats['Issuers'][issuer]['knownnotrevoked'] = known_nonrevoked_certs_len
            stats['Issuers'][issuer]['knownrevoked'] = known_revoked_certs_len

            writeCertListForIssuer(file=revfile, issuer_base64=issuer,
                                   serial_list=sets["knownRevoked"])
            writeCertListForIssuer(file=nonrevfile, issuer_base64=issuer,
                                   serial_list=sets["knownNotRevoked"])

            log.debug(f"createCertLists issuerObj={issuerObj} KNR={known_nonrevoked_certs_len} "
                      + f"KR={known_revoked_certs_len}")

    # TODO: Verify any revoked issuers that had no known issuers

    log.debug("R: %d K: %d KNR: %d KR: %d NOCRL: %d" %
              (stats['revoked'], stats['known'], stats['knownnotrevoked'],
               stats['knownrevoked'], stats['nocrl']))

    return {
        "known_nonrevoked_certs_len": stats['knownnotrevoked'],
        "known_revoked_certs_len": stats['knownrevoked'],
    }


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


def writeCertListForIssuer(*, file, issuer_base64, serial_list):
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


def readFromCertList(file):
    try:
        while True:
            (num_serial_list, issuer_len) = issuers_struct.unpack(
                                                expectRead(file, issuers_struct.size))
            issuer_bytes = expectRead(file, issuer_len)

            issuerId = getIssuerIdFromCache(issuer_bytes)

            for serial_idx in range(num_serial_list):
                (serial_len,) = serials_struct.unpack(expectRead(file, serials_struct.size))
                serial_bytes = expectRead(file, serial_len)

                yield CertId(issuerId, serial_bytes)
    except EOFException:
        pass
    return


def readFromCertListByIssuer(file):
    current_certIds = None
    current_issuer = None

    for certId in readFromCertList(file):
        if current_issuer is None:
            current_issuer = certId.issuerId
            current_certIds = set()

        elif certId.issuerId != current_issuer:
            yield (current_issuer.base64(), current_certIds)

            current_issuer = certId.issuerId
            current_certIds = set()

        current_certIds.add(certId)

    yield (current_issuer.base64(), current_certIds)


def readCertListByIssuer(file, certs_by_issuer):
    for issuer, certIds in readFromCertListByIssuer(file):
        certs_by_issuer[issuer] = certIds


def loadCertLists(*, revoked_path, nonrevoked_path, revoked_certs_by_issuer,
                  nonrevoked_certs_by_issuer):
    log.info(f"Loading revoked/nonrevoked list {revoked_path} {nonrevoked_path}")
    nonrevoked_certs_by_issuer.clear()
    revoked_certs_by_issuer.clear()
    with open(revoked_path, 'rb') as file:
        readCertListByIssuer(file, revoked_certs_by_issuer)
    with open(nonrevoked_path, 'rb') as file:
        readCertListByIssuer(file, nonrevoked_certs_by_issuer)


def getFPRs(revoked_certs_len, nonrevoked_certs_len):
    return [revoked_certs_len / (math.sqrt(2) * nonrevoked_certs_len), 0.5]


def generateMLBF(args, stats, *, revoked_certs, nonrevoked_certs, nonrevoked_certs_len):
    sw.start('mlbf')
    fprs = getFPRs(len(revoked_certs), nonrevoked_certs_len)

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
    if args.noVerify is False:
        sw.start('verify')
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
        "-onlyUseCache",
        help="Load revoked/non-revoked sorted certs from cache files, do not read the knownPath "
             + "or revokedPath folders",
        action="store_true")
    parser.add_argument(
        "-noVerify", help="Skip MLBF verification", action="store_true")
    args = parser.parse_args(argv)
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

    stats = {}
    known_nonrevoked_certs_len = None

    sw.start('crlite')
    sw.start('certs')
    if args.onlyUseCache is False:
        sw.start('collate certs')
        log.debug("constructing known revoked nonrevoked cert sets")
        results = createCertLists(
            known_path=args.knownPath,
            revoked_path=args.revokedPath,
            known_revoked_path=args.revokedKeys,
            known_nonrevoked_path=args.validKeys,
            exclude_issuer=args.excludeIssuer,
            stats=stats,
        )
        known_nonrevoked_certs_len = results["known_nonrevoked_certs_len"]
        sw.end('collate certs')

    log.debug("revoked_certs loading...")
    sw.start('load revoked certs')
    with open(args.revokedKeys, "rb") as fp:
        revoked_certs = set(readFromCertList(fp))
    num_revoked_certs = len(revoked_certs)
    sw.end('load revoked certs')
    sw.end('certs')

    # Setup for diff if previous filter specified
    # if args.previd is not None:
    #     diff_revoked_path = os.path.join(args.certPath, args.previd, "list-revoked.keys")
    #     diff_valid_path = os.path.join(args.certPath, args.previd, "list-valid.keys")
    #     if not (os.path.isfile(diff_revoked_path) and os.path.isfile(diff_valid_path)):
    #         log.warning("Previous ID specified but no filter files found.")
    #     else:
    #         prior_revoked_certs = None
    #         sw.start('load previous revoked filter')
    #         with open(diff_revoked_path, "rb") as fp:
    #             prior_revoked_certs = set(readFromCertList(fp))
    #         sw.end('load previous revoked filter')

    #         prior_revoked_certs_by_issuer = {}
    #         prior_nonrevoked_certs_by_issuer = {}

    #         loadCertLists(
    #             revoked_path=diff_revoked_path,
    #             nonrevoked_path=diff_valid_path,
    #             revoked_certs_by_issuer=prior_revoked_certs_by_issuer,
    #             nonrevoked_certs_by_issuer=prior_nonrevoked_certs_by_issuer)
    #         sw.end('load previous filter')

    #         sw.start('make diff')
    #         revoked_diff_by_isssuer = find_additions(
    #             old_by_issuer=prior_revoked_certs_by_issuer,
    #             new_by_issuer=revoked_certs_by_issuer)
    #         nonrevoked_diff_by_issuer = find_additions(
    #             old_by_issuer=prior_nonrevoked_certs_by_issuer,
    #             new_by_issuer=nonrevoked_certs_by_issuer)

    #         save_additions(
    #             out_path=args.diffPath,
    #             revoked_by_issuer=revoked_diff_by_isssuer,
    #             nonrevoked_by_issuer=nonrevoked_diff_by_issuer)
    #         sw.end('make diff')

    if not known_nonrevoked_certs_len:
        log.debug("known_nonrevoked_certs_len not calculated, calculating...")
        sw.start('calculate known_nonrevoked_certs_len')
        with open(args.validKeys, "rb") as fp:
            known_nonrevoked_certs_len = len(list(readFromCertList(fp)))
        sw.end('calculate known_nonrevoked_certs_len')

    log.debug(f"Cert lists revoked R: {num_revoked_certs} NR: {known_nonrevoked_certs_len}")

    if num_revoked_certs == 0:
        sys.exit(1)

    log.info(f"diffs complete. memory={psutil.virtual_memory()}")

    # Generate new filter
    sw.start('generate MLBF')
    with open(args.validKeys, "rb") as fp:
        mlbf = generateMLBF(
            args, stats, revoked_certs=revoked_certs,
            nonrevoked_certs=readFromCertList(fp),
            nonrevoked_certs_len=known_nonrevoked_certs_len,
        )
    sw.end('generate MLBF')

    log.info(f"generateMLBF complete. memory={psutil.virtual_memory()}")

    if mlbf.bitCount() > 0:
        with open(args.validKeys, "rb") as fp:
            verifyMLBF(
                args,
                mlbf,
                revoked_certs=revoked_certs,
                nonrevoked_certs=readFromCertList(fp))

        saveMLBF(args, stats, mlbf)

    log.info(f"verifyMLBF complete. memory={psutil.virtual_memory()}")

    saveStats(args, stats)
    sw.end('crlite')
    log.info(sw.format_last_report())


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    main()
