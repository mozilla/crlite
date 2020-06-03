#!/bin/bash -e

workflow=${crlite_workflow:-~/go/src/github.com/mozilla/crlite/workflow}

source ${workflow}/0-set_credentials.inc

cmd="${crlite_bin:-~/go/bin}/ct-fetch -log_dir ${crlite_log:-/tmp}/ -stderrthreshold=WARNING"

echo "Starting: ${cmd}"
echo "Expect ${outputRefreshPeriod} lag for initial output."

if [ -x /usr/bin/time ] ; then
  /usr/bin/time ${cmd}
else
  ${cmd}
fi

exit 0
