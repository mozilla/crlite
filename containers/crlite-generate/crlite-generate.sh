#!/bin/bash -e

workflow=${crlite_workflow:-~/go/src/github.com/mozilla/crlite/workflow}

source ${workflow}/0-set_credentials.inc

${workflow}/6-cleanup-expired-ct-folders

ID=$(${workflow}/0-allocate_identifier --path ${crlite_processing:-/ct/processing/})
echo "Allocated ${ID}"

ulimit -a

${workflow}/2-produce_revocation_data ${ID}
${workflow}/3-produce_known_data ${ID}

echo "crlite-fullrun: list known folder"
ls -latS ${ID}/known | head
echo "crlite-fullrun: list revoked folder"
ls -latS ${ID}/revoked | head
echo "crlite-fullrun: disk usage"
du -hc ${ID}

${workflow}/4-generate_mlbf ${ID}

if [ "x${DoNotUpload}x" == "xx" ] ; then
  ${workflow}/8-upload_artifacts_to_storage ${ID} --extra_folders ${crlite_persistent:-/ct}/crls:crls
fi

# ${workflow}/7-cleanup-expired-processing-folders --keep 1 --path ${crlite_processing:-/ct/processing}
# TODO: Cleanup CRL folders

echo "crlite_processing"
df ${crlite_processing:-/ct/processing}
echo "crlite_persistent"
df ${crlite_persistent:-/ct/}
