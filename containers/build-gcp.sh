#!/bin/bash -xe
TAG=testing

cd $(dirname $0)
gcloud config set project ${crlite_project:-crlite-beta}

gcloud builds submit --config ./cloudbuild.yaml --substitutions _CRLITE_TAG=${TAG} ..

kubectl set image deployment/crlite-fetch crlite-fetch=gcr.io/crlite-beta/crlite:${TAG}-fetch
kubectl set image cronjob/crlite-generate crlite-generate=gcr.io/crlite-beta/crlite:${TAG}-generate
kubectl set image cronjob/crlite-publish crlite-publish=gcr.io/crlite-beta/crlite:${TAG}-publish
