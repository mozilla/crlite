#!/bin/bash

WORKFLOW="${crlite_workflow:-/app/workflow}"
BIN="${crlite_bin:-/app}"
SCRIPTS="${BIN}/scripts"
OUTPUT="${crlite_processing:-/processing}/crlite_db"
RUST_QUERY_CRLITE="${BIN}/rust-query-crlite"
MAX_FILTER_SIZE=${max_filter_size:-10485760}

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

# sign off on cert-revocations if the verification domains test passes and the
# filter is less than MAX_FILTER_SIZE.
FILTER_SIZE=$(stat --format=%s "${OUTPUT}/crlite.filter")
echo "Filter is ${FILTER_SIZE} bytes."

if (( FILTER_SIZE > MAX_FILTER_SIZE ))
then
  echo "Cannot automatically sign off on a filter larger than max_filter_size=${MAX_FILTER_SIZE} bytes."
  exit 1;
fi

if ! "${RUST_QUERY_CRLITE}" -vvv --db "${OUTPUT}" --update "${INSTANCE}" signoff "${crlite_verify_host_file_urls}"
then
  echo "Verification domains test failed"
  exit 1;
fi

echo "Running signoff tool"
python3 "${SCRIPTS}/crlite-signoff-tool.py" cert-revocations
