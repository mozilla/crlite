#!/bin/bash -e

${crlite_bin:-~/go/bin}/commit -stderrthreshold=INFO -alsologtostderr

exit 0
