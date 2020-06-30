#!/bin/bash -e

workflow=${crlite_workflow:-~/go/src/github.com/mozilla/crlite/workflow}

source ${workflow}/0-set_credentials.inc

if [ "x${DoNotUpload}x" != "xx" ] || [ "x${KINTO_NOOP}x" != "xx" ] ; then
  ARGS="--noop"
  echo "Setting argument ${ARGS}"
fi

python3 /app/scripts/crlite-signoff-tool.py \
  --filter-bucket ${crlite_filter_bucket:-crlite_filters_staging} \
  --moz-crlite-query /app/.local/bin/moz_crlite_query \
  --hosts ${crlite_verify_hosts:-revoked.badssl.com}

moz_kinto_publisher/main.py --crlite --approve-sign ${ARGS}

moz_kinto_publisher/main.py --intermediates --approve-sign ${ARGS}

exit 0
