#!/usr/bin/env python3

from pathlib import Path
from google.api_core import exceptions

import argparse
import logging
import subprocess
import sys
import tempfile
import workflow

parser = argparse.ArgumentParser()
parser.add_argument(
    "--filter-bucket", help="Google Cloud Storage filter bucket name", required=True
)
parser.add_argument(
    "--moz-crlite-query", help="Path to the moz-crlite-query tool", required=True
)
parser.add_argument(
    "--hosts",
    help="Hosts to check, in the form host[:port] where "
    + "port is assumed 443 if not provided",
    nargs="+",
    default=[],
    metavar="host[:port]",
)


def main():
    log = logging.getLogger("signoff-tool")
    args = parser.parse_args()

    try:
        with tempfile.TemporaryDirectory() as tempDir:
            latest = workflow.get_run_identifiers(args.filter_bucket).pop()

            timestamp = workflow.download_from_google_cloud_to_string(
                args.filter_bucket, f"{latest}/timestamp"
            )

            filter_path = Path(tempDir) / f"{timestamp.decode('utf-8')}Z-full"

            workflow.download_from_google_cloud(
                args.filter_bucket, f"{latest}/mlbf/filter", filter_path,
            )

            sub_args = [
                sys.executable,
                args.moz_crlite_query,
                "--use-filter",
                filter_path,
                "--check-not-revoked",
                "--hosts",
            ]
            sub_args += args.hosts

            log.info(f"Running {sub_args}")
            subprocess.run(sub_args, check=True)

    except exceptions.NotFound as e:
        log.fatal(f"Could not download existing filter: {e}")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        log.fatal(f"Error in moz_crlite_query: {e}")
        sys.exit(1)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
