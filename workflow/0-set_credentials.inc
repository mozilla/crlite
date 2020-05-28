#!/bin/bash -e

if [ "x${credentials_data}x" != "xx" ] ; then
  echo "Using the credentials_data evironment variable for GOOGLE_APPLICATION_CREDENTIALS"
  echo "${credentials_data}" | base64 --decode >> /tmp/credentials.json
  export GOOGLE_APPLICATION_CREDENTIALS=/tmp/credentials.json
fi

if [ "x${GOOGLE_APPLICATION_CREDENTIALS}x" == "xx" ] ; then
  echo "You'll need to provide GOOGLE_APPLICATION_CREDENTIALS somehow"
  echo "because all the scripts depend on it. Maybe you should also set"
  echo "DoNotUpload to something, to avoid uploading accidentally?"
  exit 1
fi
