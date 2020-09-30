#!/bin/bash -e

workflow=${crlite_workflow:-~/go/src/github.com/mozilla/crlite/workflow}

source ${workflow}/0-set_credentials.inc

if [ "x${DoNotUpload}x" != "xx" ] || [ "x${KINTO_NOOP}x" != "xx" ] ; then
  ARGS="--noop"
  echo "Setting argument ${ARGS}"
fi

python3 /app/scripts/crlite-signoff-tool.py \
  --moz-crlite-query /usr/local/bin/moz_crlite_query \
  --host-file-urls ${crlite_verify_host_file_urls}

moz_kinto_publisher/main.py --crlite --approve-sign ${ARGS}

moz_kinto_publisher/main.py --intermediates --approve-sign ${ARGS}

exit 0
