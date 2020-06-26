#!/bin/bash -e

workflow=${crlite_workflow:-~/go/src/github.com/mozilla/crlite/workflow}

source ${workflow}/0-set_credentials.inc

echo "Expect ${outputRefreshPeriod} lag for initial output."

${crlite_bin:-~/go/bin}/ct-fetch -nobars -logtostderr -stderrthreshold=INFO

exit 0
