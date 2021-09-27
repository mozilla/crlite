#!/bin/bash -e

${crlite_bin:-~/go/bin}/ct-fetch -logtostderr -stderrthreshold=INFO

exit 0
