#!/bin/bash -e

workflow=${crlite_workflow:-~/go/src/github.com/mozilla/crlite/workflow}

source ${workflow}/0-set_credentials.inc

ID=$(${workflow}/0-allocate_identifier \
              --path ${crlite_processing:-/ct/processing/} \
              --filter-bucket ${crlite_filter_bucket:-crlite_filters_staging})

echo "Allocated ${ID}"

ulimit -a

if [ ! -d ${ID}/log ] ; then
  mkdir ${ID}/log
fi

${crlite_bin:-~/go/bin}/aggregate-crls -crlpath ${crlite_persistent:-/ct}/crls \
              -revokedpath ${ID}/revoked \
              -enrolledpath ${ID}/enrolled.json \
              -auditpath ${ID}/crl-audit.json \
              -ccadb ${crlite_persistent:-/ct}/ccadb-intermediates.csv \
              -stderrthreshold=INFO -alsologtostderr \
              -log_dir ${ID}/log

${crlite_bin:-~/go/bin}/aggregate-known -knownpath ${ID}/known \
              -enrolledpath ${ID}/enrolled.json \
              -stderrthreshold=INFO -alsologtostderr \
              -log_dir ${WORKDIR}/log


echo "crlite-fullrun: list known folder"
ls -latS ${ID}/known | head
echo "crlite-fullrun: list revoked folder"
ls -latS ${ID}/revoked | head
echo "crlite-fullrun: disk usage"
du -hc ${ID}

${workflow}/1-generate_mlbf ${ID} \
              --filter-bucket ${crlite_filter_bucket:-crlite_filters_staging}

if [ "x${DoNotUpload}x" == "xx" ] ; then
  ${workflow}/2-upload_artifacts_to_storage ${ID} \
              --filter-bucket ${crlite_filter_bucket:-crlite_filters_staging} \
              --extra_folders ${crlite_persistent:-/ct}/crls:crls
fi

echo "crlite_processing"
df ${crlite_processing:-/ct/processing}
echo "crlite_persistent"
df ${crlite_persistent:-/ct/}

exit 0
