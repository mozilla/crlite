#!/usr/bin/env python3

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import base64
import logging
import os
import struct

from pathlib import Path

log = logging.getLogger("create_filter_cascade")

# bytes 0-3: N, number of serials as an unsigned long
# byte 4: L, length of issuer field as a unsigned char
# bytes 5+: hash of issuer subject public key info of length L
# then N serials_structs
issuers_struct = struct.Struct(b"<LB")

# byte 0: length of serial field as an unsigned short
# bytes 1+: serial number
serials_struct = struct.Struct(b"<B")

# bytes 0-3: N, number of revoked serials as an unsigned long
# byte 4: L, length of issuer field as a unsigned char
# bytes 5+: hash of issuer subject public key info of length L
# then N serials_structs followed by M serials_structs
additions_struct = struct.Struct(b"<LB")

issuerCache = {}


class EOFException(Exception):
    pass


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

    def __len__(self):
        return len(self.issuerSpkiHash)


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
            stats["known"] += len(knownSet)
        else:
            knownSet = set()
        stats["Issuers"][self.issuer]["known"] = len(knownSet)

        revSet = getCertList(self.revokedPath, self.issuer)
        if revSet:
            stats["revoked"] += len(revSet)
            stats["Issuers"][self.issuer]["crl"] = True
        else:
            stats["nocrl"] += 1
            revSet = set()
        stats["Issuers"][self.issuer]["revoked"] = len(revSet)

        knownNotRevoked = knownSet - revSet
        knownRevoked = knownSet & revSet
        return {
            "issuer": self.issuer,
            "knownNotRevoked": knownNotRevoked,
            "knownRevoked": knownRevoked,
        }


def getIssuerIdFromCache(issuerSpkiHash):
    if not isinstance(issuerSpkiHash, bytes):
        raise Exception("issuerSpkiHash must be bytes")

    if issuerSpkiHash not in issuerCache:
        issuerCache[issuerSpkiHash] = IssuerId(issuerSpkiHash)

    return issuerCache[issuerSpkiHash]


def getCertList(certpath_str, issuer):
    issuerId = getIssuerIdFromCache(base64.urlsafe_b64decode(issuer))

    certpath = Path(certpath_str)

    certlist = set()
    if not certpath.is_file():
        log.error(f"getCertList couldn't find file {certpath}")
        return None

    log.debug(f"getCertList opening {certpath} (sz={certpath.stat().st_size})")

    with open(certpath, "r") as f:
        try:
            for cnt, sHex in enumerate(f):
                try:
                    serial = bytes.fromhex(sHex)
                    certlist.add(CertId(issuerId, serial))
                except ValueError as te:
                    log.error(
                        f"Couldn't decode line={cnt} issuer={issuer} serial "
                        + f"hex={sHex} because {te}"
                    )
        except Exception as e:
            log.debug(f"getCertList exception caught: {type(e)} {e}")
            log.error(f"Failed to load certs for {issuer} from {certpath}")
            breakpoint()
    return certlist


def genIssuerPathObjects(*, knownPath, revokedPath, excludeIssuer):
    for path, dirs, files in os.walk(knownPath):
        for filename in files:
            issuer = os.path.splitext(filename)[0]
            if issuer in excludeIssuer:
                continue

            yield IssuerDataOnDisk(
                issuer=issuer,
                knownPath=path / Path(filename),
                revokedPath=revokedPath / Path(issuer),
            )


def writeSerials(file, serial_list):
    for k in serial_list:
        n = len(k.serial)
        if n > 0xFF:
            raise ValueError("serial bytes > unsigned short")
        file.write(serials_struct.pack(n))
        file.write(k.serial)


def writeCertListForIssuer(*, file, issuer_base64, serial_list):
    num_serial_list = len(serial_list)

    issuer = base64.urlsafe_b64decode(issuer_base64)
    issuer_len = len(issuer)

    if num_serial_list > 0xFFFFFFFF:
        raise ValueError("serial list length > unsigned long")
    if issuer_len > 0xFF:
        raise ValueError("issuer bytes > unsigned char")

    file.write(issuers_struct.pack(num_serial_list, issuer_len))
    file.write(issuer)

    writeSerials(file, serial_list)


def save_additions(*, out_path, revoked_by_issuer):
    with open(out_path, "wb") as file:
        for issuer_b64, issuer_revocations in revoked_by_issuer.items():
            issuer = base64.urlsafe_b64decode(issuer_b64)
            issuer_len = len(issuer)
            if issuer_len > 0xFF:
                raise ValueError("issuer bytes > unsigned char")

            num_issuer_revocations = len(issuer_revocations)
            if num_issuer_revocations > 0xFFFFFFFF:
                raise ValueError("revocation list length > unsigned long")

            file.write(additions_struct.pack(num_issuer_revocations, issuer_len))
            file.write(issuer)

            writeSerials(file, issuer_revocations)


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


def readFromAdditionsList(file):
    try:
        while True:
            (num_issuer_revocations, issuer_len) = additions_struct.unpack(
                expectRead(file, additions_struct.size)
            )
            assert issuer_len <= 64, (
                f"issuer spki hash should be 64 bytes, got {issuer_len} "
                + f"at offset {file.tell()} of {file.name}"
            )
            issuer_bytes = expectRead(file, issuer_len)

            issuerId = getIssuerIdFromCache(issuer_bytes)

            revSet = set()
            for serial_idx in range(num_issuer_revocations):
                (serial_len,) = serials_struct.unpack(
                    expectRead(file, serials_struct.size)
                )
                assert serial_len <= 64, (
                    f"serial length should be small, got {serial_len} "
                    + f"at offset {file.tell()} of {file.name}"
                )
                serial_bytes = expectRead(file, serial_len)
                revSet.add(CertId(issuerId, serial_bytes))

            yield {"issuerId": issuerId, "revocations": revSet}

    except EOFException:
        return


def readFromCertList(file):
    try:
        while True:
            (num_serial_list, issuer_len) = issuers_struct.unpack(
                expectRead(file, issuers_struct.size)
            )
            assert issuer_len <= 64, (
                f"issuer spki hash should be 64 bytes, got {issuer_len} "
                + f"at offset {file.tell()} of {file.name}"
            )
            issuer_bytes = expectRead(file, issuer_len)

            issuerId = getIssuerIdFromCache(issuer_bytes)

            for serial_idx in range(num_serial_list):
                (serial_len,) = serials_struct.unpack(
                    expectRead(file, serials_struct.size)
                )
                assert serial_len <= 64, (
                    f"serial length should be small, got {serial_len} "
                    + f"at offset {file.tell()} of {file.name}"
                )
                serial_bytes = expectRead(file, serial_len)

                yield CertId(issuerId, serial_bytes)
    except EOFException:
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

    if current_issuer is None:
        # file did not contain any cert IDs
        return

    yield (current_issuer.base64(), current_certIds)
