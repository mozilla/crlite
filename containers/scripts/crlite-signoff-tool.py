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
    "KINTO_RW_SERVER_URL", default="https://settings-writer.stage.mozaws.net/v1/"
)
KINTO_RO_SERVER_URL = config(
    "KINTO_RO_SERVER_URL", default="https://settings-cdn.stage.mozaws.net/v1/"
)
KINTO_AUTH_USER = config("KINTO_AUTH_USER", default="")
KINTO_AUTH_PASSWORD = config("KINTO_AUTH_PASSWORD", default="")
KINTO_BUCKET = config("KINTO_BUCKET", default="security-state-staging")
KINTO_CRLITE_COLLECTION = config("KINTO_CRLITE_COLLECTION", default="cert-revocations")
KINTO_INTERMEDIATES_COLLECTION = config(
    "KINTO_INTERMEDIATES_COLLECTION", default="intermediates"
)
KINTO_NOOP = config("KINTO_NOOP", default=False, cast=lambda x: bool(x))

CRLITE_FRESHNESS_HOURS = config("CRLITE_FRESHNESS_HOURS", default="2")


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


def download_host_file(filename, output_dir, host_url):
    headers = {"X-Automated-Tool": "https://github.com/mozilla/crlite"}
    hosts_file_path = Path(output_dir) / filename
    r = requests.get(host_url, headers=headers)
    r.raise_for_status()
    with hosts_file_path.open("wb") as fd:
        fd.write(r.content)
    log.info(
        f"Downloaded {host_url} to {hosts_file_path} "
        + f"(sz={hosts_file_path.stat().st_size})"
    )


if __name__ == "__main__":
    OK = 0
    ERROR = 1

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--noop", default=KINTO_NOOP, action="store_true", help="Don't update Kinto"
    )
    parser.add_argument(
        "--moz-crlite-query", help="Path to the moz-crlite-query tool", required=True
    )
    parser.add_argument(
        "--host-file-urls",
        help="URLs of host files to download and check, comma or space (or both) delimited",
        nargs="+",
        default=[],
        metavar="url",
    )
    args = parser.parse_args()

    sub_args = [
        sys.executable,
        args.moz_crlite_query,
        "--force-update",
        "--crlite-url",
        KINTO_RO_SERVER_URL
        + str(
            Path("buckets")
            / KINTO_BUCKET
            / "collections"
            / KINTO_CRLITE_COLLECTION
            / "records"
        ),
        "--check-not-revoked",
        "--check-freshness",
        CRLITE_FRESHNESS_HOURS,
        "--structured",
    ]

    with tempfile.TemporaryDirectory() as temp_dir:
        sub_args.extend(["--db", temp_dir])
        for url in args.host_file_urls:
            filename = hashlib.sha256(url.encode("utf-8")).hexdigest()
            try:
                download_host_file(filename, temp_dir, url)
            except requests.exceptions.HTTPError as e:
                log.error(f"Could not download hosts file to check: {e}")
                sys.exit(ERROR)
            sub_args.extend(["--hosts-file", str(Path(temp_dir) / filename)])

        log.info(f"Running {sub_args}")
        try:
            subprocess.run(sub_args, check=True)
        except subprocess.CalledProcessError as e:
            log.error(f"Error in moz_crlite_query: {e}")
            sys.exit(ERROR)

    if args.noop:
        log.info("Would sign off, but noop requested")
        sys.exit(OK)

    auth = requests.auth.HTTPBasicAuth(KINTO_AUTH_USER, KINTO_AUTH_PASSWORD)
    rw_client = SignoffClient(
        server_url=KINTO_RW_SERVER_URL,
        auth=auth,
        bucket=KINTO_BUCKET,
        retry=5,
    )

    try:
        rw_client.sign_collection(collection=KINTO_CRLITE_COLLECTION)
        rw_client.sign_collection(collection=KINTO_INTERMEDIATES_COLLECTION)
    except KintoException as e:
        log.error(f"Kinto exception: {e}")
        sys.exit(ERROR)

    sys.exit(OK)
