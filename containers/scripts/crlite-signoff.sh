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

# sign off on cert-revocations if verification domains test passes
if "${RUST_QUERY_CRLITE}" -vvv --db "${OUTPUT}" --update "${INSTANCE}" signoff "${crlite_verify_host_file_urls}"
then
  python3 "${SCRIPTS}/crlite-signoff-tool.py" cert-revocations
fi

