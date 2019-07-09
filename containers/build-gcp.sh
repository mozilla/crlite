#!/bin/bash -xe

gcloud config set project ${crlite_project:-crlite-beta}
gcloud builds submit --config ./cloudbuild.yaml ..
