#!/usr/bin/env python3

from decouple import config
from google.api_core import exceptions
from pathlib import Path

import argparse
import hashlib
import logging
import requests
import subprocess
import sys
import tempfile

KINTO_RO_SERVER_URL = config(
    "KINTO_RO_SERVER_URL", default="https://settings.stage.mozaws.net/v1/"
)
KINTO_BUCKET = config("KINTO_BUCKET", default="security-state-preview")
KINTO_CRLITE_COLLECTION = config("KINTO_CRLITE_COLLECTION", default="cert-revocations")
CRLITE_FRESHNESS_HOURS = config("CRLITE_FRESHNESS_HOURS", default="2")

parser = argparse.ArgumentParser()
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


def main():
    log = logging.getLogger("signoff-tool")
    args = parser.parse_args()

    headers = {"X-Automated-Tool": "https://github.com/mozilla/crlite"}

    try:
        with tempfile.TemporaryDirectory() as tempDir:
            sub_args = [
                sys.executable,
                args.moz_crlite_query,
                "--force-update",
                "--db",
                tempDir,
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

            for host_url in args.host_file_urls:
                host_url = host_url.strip(", ")
                filename = hashlib.sha256(host_url.encode("utf-8")).hexdigest()
                hosts_file_path = Path(tempDir) / filename
                r = requests.get(host_url, headers=headers)
                r.raise_for_status()
                with hosts_file_path.open("wb") as fd:
                    for chunk in r.iter_content(chunk_size=1024):
                        fd.write(chunk)
                sub_args.extend(["--hosts-file", str(hosts_file_path)])
                log.info(
                    f"Downloaded {host_url} to {hosts_file_path} "
                    + f"(sz={hosts_file_path.stat().st_size})"
                )

            log.info(f"Running {sub_args}")
            subprocess.run(sub_args, check=True)

    except requests.exceptions.HTTPError as e:
        log.fatal(f"Could not download hosts file to check: {e}")
        sys.exit(1)
    except exceptions.NotFound as e:
        log.fatal(f"Could not download existing filter: {e}")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        log.fatal(f"Error in moz_crlite_query: {e}")
        sys.exit(1)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
