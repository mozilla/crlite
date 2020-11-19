#!/bin/bash
cd go

go test -tags=unit -short -timeout 30s -v ./...

returncode=$?
if [ $returncode -ne 0 ]; then
  echo "unit tests failed"
  exit 1
fi
