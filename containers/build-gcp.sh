#!/bin/bash -xe
cd $(dirname $0)
gcloud config set project ${crlite_project:-crlite-beta}
gcloud builds submit --config ./cloudbuild.yaml ..
