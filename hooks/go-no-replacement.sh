#!/bin/bash

if grep "replace github.com/jcjones/ct-mapreduce" $@ 2>&1 >/dev/null ; then
  echo "ERROR: Don't commit a replacement in go.mod!"
  exit 1
fi
