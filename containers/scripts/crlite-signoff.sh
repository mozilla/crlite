#!/bin/bash

WORKFLOW="${crlite_workflow:-/app/workflow}"
BIN="${crlite_bin:-/app}"
SCRIPTS="${BIN}/scripts"
OUTPUT="${crlite_processing:-/processing}/crlite_db"
RUST_QUERY_CRLITE="${BIN}/rust-query-crlite"

source "${WORKFLOW}/0-set_credentials.inc"

if [[ "${crlite_filter_bucket}" == "crlite-filters-prod" ]]; then
  INSTANCE="prod"
elif [[ "${crlite_filter_bucket}" == "crlite-filters-stage" ]]; then
  INSTANCE="stage"
elif [[ "${crlite_filter_bucket}" == "crlite-filters-dev" ]]; then
  INSTANCE="dev"
else
  echo "Cannot map ${crlite_filter_bucket} to known instance"
  exit 1;
fi

# sign off on intermediates
python3 "${SCRIPTS}/crlite-signoff-tool.py" intermediates

# Sign off on cert-revocations if the verification domains test passes and the
# filter is less than 10 MB.
if "${RUST_QUERY_CRLITE}" -vvv --db "${OUTPUT}" --update "${INSTANCE}" signoff "${crlite_verify_host_file_urls}"
then
  if (( $(stat --format=%s "${OUTPUT}/crlite.filter") < 10*1024*1024 ))
  then
    python3 "${SCRIPTS}/crlite-signoff-tool.py" cert-revocations
  fi
fi

