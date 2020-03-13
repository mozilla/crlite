#!/usr/bin/env python3

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from collections import Counter
from pathlib import Path
import argparse
import certs_to_crlite
import logging


def read_keys(path, emit=False):
    cnt = Counter()
    issuers = Counter()
    issuerLen = Counter()
    serialLen = Counter()

    with open(path, "rb") as fp:
        for certId in certs_to_crlite.readFromCertList(fp):
            cnt["serials"] += 1

            issuers[certId.issuerId] += 1

            issuerLen[len(certId.issuerId)] += 1
            serialLen[len(certId.serial)] += 1

            if emit:
                print(f"{certId}")

    print(f"Issuers: {len(issuers)} Most Common: {issuers.most_common(5)} Serials: {cnt}")
    print(f"Issuer Lengths: {issuerLen.most_common(5)} Serial Lengths: {serialLen.most_common(5)}")


def main():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-keys",
        type=Path,
        help="Path to a .keys binary file"
    )
    group.add_argument(
        "-stash",
        type=Path,
        help="Path to a .stash binary file"
    )

    parser.add_argument(
        "-print",
        help="Print the values",
        action="store_true"
    )
    args = parser.parse_args()

    if args.keys:
        read_keys(args.keys, emit=args.print)
    if args.stash:
        raise Exception("not implemented")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    main()
