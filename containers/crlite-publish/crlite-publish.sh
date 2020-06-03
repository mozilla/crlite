#!/bin/bash -e

workflow=${crlite_workflow:-~/go/src/github.com/mozilla/crlite/workflow}

source ${workflow}/0-set_credentials.inc

if [ "x${DoNotUpload}x" != "xx" ] || [ "x${KINTO_NOOP}x" != "xx" ] ; then
  ARGS="--noop"
  echo "Setting argument ${ARGS}"
fi

mkdir /tmp/crlite /tmp/intermediates

moz_kinto_publisher/main.py --crlite --download-path /tmp/crlite --request-review ${ARGS}

moz_kinto_publisher/main.py --intermediates --download-path /tmp/intermediates --request-review ${ARGS}

exit 0
