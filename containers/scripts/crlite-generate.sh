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

CRLS=${crlite_persistent:-/ct}/crls
${crlite_bin:-~/go/bin}/aggregate-crls -crlpath ${CRLS} \
              -revokedpath ${ID}/revoked \
              -enrolledpath ${ID}/enrolled.json \
              -auditpath ${ID}/crl-audit.json \
              -ccadb ${crlite_persistent:-/ct}/ccadb-intermediates.csv \
              -stderrthreshold=INFO -alsologtostderr \
              -log_dir ${ID}/log

${crlite_bin:-~/go/bin}/aggregate-known -knownpath ${ID}/known \
              -enrolledpath ${ID}/enrolled.json \
              -ctlogspath ${ID}/ct-logs.json \
              -stderrthreshold=INFO -alsologtostderr \
              -log_dir ${WORKDIR}/log

# Mark the known and revoked directories as read-only.
# rust-create-cascade assumes they will not change during its execution.
chmod -R a-w "${ID}/known"
chmod -R a-w "${ID}/revoked"

echo "crlite-fullrun: list known folder"
ls -latS ${ID}/known | head
echo "crlite-fullrun: list revoked folder"
ls -latS ${ID}/revoked | head
echo "crlite-fullrun: disk usage"
du -hc ${ID}

if [ "x${DoNotUpload}x" == "xx" ] ; then
  echo "archiving crls"
  tar -czf ${ID}/crls.tar.gz -C ${CRLS} .
  echo "uploading source materials"
  ${workflow}/1-upload_data_to_storage ${ID} \
              --filter-bucket ${crlite_filter_bucket:-crlite_filters_staging}
fi

${workflow}/2-generate_mlbf ${ID} \
              --filter-bucket ${crlite_filter_bucket:-crlite_filters_staging} \
              --statsd-host ${statsdHost} \
              --reason-set all \
              --filter-type clubcard

${workflow}/2-generate_mlbf ${ID} \
              --filter-bucket ${crlite_filter_bucket:-crlite_filters_staging} \
              --statsd-host ${statsdHost} \
              --reason-set priority \
              --filter-type clubcard

if [ "x${DoNotUpload}x" == "xx" ] ; then
  echo "uploading mlbf"
  ${workflow}/3-upload_mlbf_to_storage ${ID} \
              --filter-bucket ${crlite_filter_bucket:-crlite_filters_staging}
fi

echo "crlite_processing"
df ${crlite_processing:-/ct/processing}
echo "crlite_persistent"
df ${crlite_persistent:-/ct/}

exit 0
