#!/bin/bash -e

workflow=${crlite_workflow:-~/go/src/github.com/mozilla/crlite/workflow}

source ${workflow}/0-set_credentials.inc

python3 /app/scripts/crlite-signoff-tool.py \
  --moz-crlite-query /usr/local/bin/moz_crlite_query \
  --host-file-urls ${crlite_verify_host_file_urls}
