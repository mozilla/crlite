#!/bin/bash -e

workflow=${crlite_workflow:-~/go/src/github.com/mozilla/crlite/workflow}

source ${workflow}/0-set_credentials.inc

cmd="${crlite_bin:-~/go/bin}/reprocess-known-certs -logtostderr"
echo "Starting ${cmd}..."

if [ -x /usr/bin/time ] ; then
  /usr/bin/time ${cmd}
else
  ${cmd}
fi
