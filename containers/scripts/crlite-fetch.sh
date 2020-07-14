#!/bin/bash -e

${crlite_bin:-~/go/bin}/ct-fetch -nobars -logtostderr -stderrthreshold=INFO

exit 0
