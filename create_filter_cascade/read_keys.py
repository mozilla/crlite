#!/usr/bin/env python3

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import binascii
import logging
import moz_crlite_lib as crlite
import sys

from collections import Counter
from pathlib import Path


def read_keys(path, *, emit=False, serial=None):
    cnt = Counter()
    issuers = Counter()
    issuerLen = Counter()
    serialLen = Counter()

    with open(path, "rb") as fp:
        for certId in crlite.readFromCertList(fp):
            cnt["serials"] += 1

            issuers[certId.issuerId] += 1

            issuerLen[len(certId.issuerId)] += 1
            serialLen[len(certId.serial)] += 1

            if emit:
                print(f"{certId}")

            if serial and certId.serial == serial:
                print(f"{certId} found")
                sys.exit(0)

    print(
        f"Issuers: {len(issuers)} Most Common: {issuers.most_common(5)} Serials: {cnt}"
    )
    print(
        f"Issuer Lengths: {issuerLen.most_common(5)} Serial Lengths: {serialLen.most_common(5)}"
    )

    if serial:
        print(f"{serial.hex()} not found, exiting 1")
        sys.exit(1)


def read_stash(path, *, emit=False, serial=None):
    cnt = Counter()
    issuers = Counter()
    revocations = Counter()
    serialLen = Counter()

    with open(path, "rb") as fp:
        for data in crlite.readFromAdditionsList(fp):
            cnt["issuers"] += 1

            issuers[data["issuerId"]] += 1
            revocations[data["issuerId"]] += len(data["revocations"])

            cnt["revocations"] += len(data["revocations"])

            for certId in data["revocations"]:
                serialLen[len(certId.serial)] += 1

            if emit:
                print(f"{data['issuerId']} new revocations: {len(data['revocations'])}")

            if serial and certId.serial == serial:
                print(f"{certId} found")
                sys.exit(0)

    print(f"Issuers Affected: {cnt['issuers']}")
    print(f"Number of New Revocations: {cnt['revocations']}")

    totalBytes = 0
    for l, qty in serialLen.items():
        totalBytes += l * qty
    print(f"Distribution of Serial Lengths: {serialLen.most_common(32)}")
    print(f"Aggregated Serials in Bytes: {totalBytes} bytes")
    print(f"Stash File Size in Bytes: {path.stat().st_size} bytes")

    if serial:
        print(f"{serial.hex()} not found, exiting 1")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-keys", type=Path, help="Path to a .keys binary file")
    group.add_argument("-stash", type=Path, help="Path to a .stash binary file")

    parser.add_argument(
        "-contains-serial", help="Check if this contains a serial (in hex)"
    )
    parser.add_argument("-print", help="Print the values", action="store_true")
    args = parser.parse_args()

    serial = None
    if args.contains_serial:
        serial = binascii.unhexlify(args.contains_serial)

    if args.keys:
        read_keys(args.keys, emit=args.print, serial=serial)
    if args.stash:
        read_stash(args.stash, emit=args.print, serial=serial)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    main()
