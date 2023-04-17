#!/usr/bin/env python3

import argparse
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

import requests
import glog as log

from decouple import config

from kinto_http import Client
from kinto_http.patch_type import BasicPatch
from kinto_http.exceptions import KintoException

KINTO_RW_SERVER_URL = config(
    "KINTO_RW_SERVER_URL", default="https://remote-settings.allizom.org/v1/"
)
KINTO_AUTH_USER = config("KINTO_AUTH_USER", default="")
KINTO_AUTH_PASSWORD = config("KINTO_AUTH_PASSWORD", default="")
KINTO_BUCKET = config("KINTO_BUCKET", default="security-state-staging")
KINTO_CRLITE_COLLECTION = config("KINTO_CRLITE_COLLECTION", default="cert-revocations")
KINTO_INTERMEDIATES_COLLECTION = config(
    "KINTO_INTERMEDIATES_COLLECTION", default="intermediates"
)
KINTO_NOOP = config("KINTO_NOOP", default=False, cast=lambda x: bool(x))


class SignoffClient(Client):
    def sign_collection(self, *, collection=None):
        try:
            resp = self.get_collection(id=collection)
        except KintoException as e:
            log.error(f"Couldn't determine {collection} review status: {e}")
            raise e

        original = resp.get("data")
        if original is None:
            raise KintoException("Malformed response from Kinto")

        status = original.get("status")
        if status is None:
            raise KintoException("Malformed response from Kinto")

        if status != "to-review":
            log.info("Collection is not marked for review. Skipping.")
            return

        try:
            resp = self.patch_collection(
                original=original, changes=BasicPatch({"status": "to-sign"})
            )
        except KintoException as e:
            log.error(f"Couldn't sign {collection}")
            raise e


if __name__ == "__main__":
    OK = 0
    ERROR = 1

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "collection",
        help="Collection to sign, either 'cert-revocations' or 'intermediates'",
    )
    parser.add_argument(
        "--noop", default=KINTO_NOOP, action="store_true", help="Don't update Kinto"
    )
    args = parser.parse_args()

    if args.collection == "cert-revocations":
        collection = KINTO_CRLITE_COLLECTION
    elif args.collection == "intermediates":
        collection = KINTO_INTERMEDIATES_COLLECTION
    else:
        log.error(f"Unknown collection {args.collection}")
        sys.exit(ERROR)

    if args.noop:
        log.info(f"Would sign off on {collection}, but noop requested")
        sys.exit(OK)

    auth = requests.auth.HTTPBasicAuth(KINTO_AUTH_USER, KINTO_AUTH_PASSWORD)
    rw_client = SignoffClient(
        server_url=KINTO_RW_SERVER_URL,
        auth=auth,
        bucket=KINTO_BUCKET,
        retry=5,
    )

    try:
        rw_client.sign_collection(collection=collection)
    except KintoException as e:
        log.error(f"Kinto exception: {e}")
        sys.exit(ERROR)

    sys.exit(OK)
