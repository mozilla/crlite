#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import subprocess
import sys
import json
import tempfile
from pathlib import Path

import requests
import glog as log

from decouple import config

from kinto_http import Client
from kinto_http.patch_type import BasicPatch
from kinto_http.exceptions import KintoException

import workflow

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

    def get_current_full_filter_id(self):
        records = self.get_records(collection=KINTO_CRLITE_COLLECTION)
        full_filters = [x for x in records if not x["incremental"]]
        if len(full_filters) == 0:
            raise KintoException("No full filter")
        if len(full_filters) > 1:
            raise KintoException("Multiple full filters")
        full_filter = full_filters[0]
        if not (
            "attachment" in full_filter and "filename" in full_filter["attachment"]
        ):
            raise KintoException("Malformed record")
        run_id = full_filter["attachment"]["filename"].rsplit("-", 1)[0]
        return run_id

    def verify_enrollment(self, *, enrollment_path):
        with enrollment_path.open("r") as f:
            aggregator_records = json.load(f)
        rs_records = self.get_records(collection=KINTO_INTERMEDIATES_COLLECTION)

        # An intermediate is identified by its Subject DN and SPKI hash
        k = lambda x: (x["subjectDN"], x["pubKeyHash"])

        # We may have multiple certificates for an intermediate. These should all
        # have the same `crlite_enrolled` value.
        rs_icas = {}
        for r in rs_records:
            if k(r) not in rs_icas:
                rs_icas[k(r)] = r
            elif r["crlite_enrolled"] != rs_icas[k(r)]["crlite_enrolled"]:
                raise KintoException(
                    f"Inconsistent enrollment for {r['subject']}--{r['pubKeyHash']}"
                )

        # The CRLite aggregator and Remote Settings should agree on enrollment
        for r in aggregator_records:
            if k(r) not in rs_icas:
                # This usually indicates that we skipped enrollment because of
                # a defect in the intermediate's certificate. The CRLite
                # aggregator and moz_kinto_publisher don't use the same library
                # for parsing x509 certs; the library that moz_kinto_publisher
                # uses is more strict.
                log.warning(
                    f"Missing remote settings record for {r['subject']}--{r['pubKeyHash']}"
                )
            elif r["enrollment"] != rs_icas[k(r)]["enrollment"]:
                raise KintoException(
                    f"Inconsistent enrollment for {r['subject']}--{r['pubKeyHash']}"
                )


def download_full_filter_enrollment(*, filter_bucket, run_id, save_path):
    workflow.download_and_retry_from_google_cloud(
        filter_bucket,
        f"{run_id}/enrolled.json",
        save_path,
        timeout=datetime.timedelta(minutes=5),
    )


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
    parser.add_argument("--filter-bucket", default="crlite_filters")
    args = parser.parse_args()

    if args.noop:
        rs_client = SignoffClient(
            server_url=KINTO_RO_SERVER_URL,
            auth=None,
            bucket=KINTO_BUCKET,
            retry=5,
        )
    else:
        auth = requests.auth.HTTPBasicAuth(KINTO_AUTH_USER, KINTO_AUTH_PASSWORD)
        rs_client = SignoffClient(
            server_url=KINTO_RW_SERVER_URL,
            auth=auth,
            bucket=KINTO_BUCKET,
            retry=5,
        )

    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            run_id = rs_client.get_current_full_filter_id()
            save_path = Path(temp_dir) / "enrolled.json"
            download_full_filter_enrollment(
                filter_bucket=args.filter_bucket, run_id=run_id, save_path=save_path
            )
            rs_client.verify_enrollment(enrollment_path=save_path)
        except Exception as e:
            log.error(f"Error verifying enrollment: {e}")
            sys.exit(ERROR)

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

    try:
        rs_client.sign_collection(collection=KINTO_CRLITE_COLLECTION)
        rs_client.sign_collection(collection=KINTO_INTERMEDIATES_COLLECTION)
    except KintoException as e:
        log.error(f"Kinto exception: {e}")
        sys.exit(ERROR)

    sys.exit(OK)
