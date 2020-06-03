#!/bin/bash -ex

cd $(dirname ${0})

my_ip=$(ipconfig getifaddr en0)

cd go
  go test ./...
cd ..

assureDir() {
  if [ ! -d ${1} ] ; then
    mkdir ${1}
  fi
}

assureDir /tmp/crlite
assureDir /tmp/crlite/processing
assureDir /tmp/crlite/persistent

if [ "x${GOOGLE_APPLICATION_CREDENTIALS}x" == "xx" ]; then
  echo "You must set GOOGLE_APPLICATION_CREDENTIALS"
  exit 1
fi

echo "Ensure Redis is running at ${my_ip}:6379 and Firestore at ${my_ip}:8403"

docker run --rm -it \
  -e "googleProjectId=crlite-beta" \
  -e "FIRESTORE_EMULATOR_HOST=${my_ip}:8403" \
  -e "redisHost=${my_ip}:6379" \
  -e "credentials_data=$(base64 ${GOOGLE_APPLICATION_CREDENTIALS})" \
  -e "DoNotUpload=true" \
  -e "outputRefreshMs=1000" \
  -e "logList=https://ct.googleapis.com/logs/argon2021/, https://ct.googleapis.com/logs/argon2022/, https://ct.googleapis.com/logs/argon2023/" \
  -e "limit=500" \
  -e "runForever=false" \
  crlite:0.1-fetch

docker run --rm -it \
  -e "googleProjectId=crlite-beta" \
  -e "FIRESTORE_EMULATOR_HOST=${my_ip}:8403" \
  -e "redisHost=${my_ip}:6379" \
  -e "credentials_data=$(base64 ${GOOGLE_APPLICATION_CREDENTIALS})" \
  -e "DoNotUpload=true" \
  -e "outputRefreshMs=1000" \
  --mount type=bind,src=/tmp/crlite/persistent,dst=/persistent \
  --mount type=bind,src=/tmp/crlite/processing,dst=/processing \
  crlite:0.1-generate

docker run --rm -it \
  -e "googleProjectId=crlite-beta" \
  -e "FIRESTORE_EMULATOR_HOST=${my_ip}:8403" \
  -e "redisHost=${my_ip}:6379" \
  -e "credentials_data=$(base64 ${GOOGLE_APPLICATION_CREDENTIALS})" \
  -e "DoNotUpload=true" \
  -e "outputRefreshMs=1000" \
  crlite:0.1-publish
