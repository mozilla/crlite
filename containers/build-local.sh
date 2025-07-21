#!/bin/bash -xe

VER=staging

cd $(dirname ${0})
docker build -t crlite:${VER} .. -f Dockerfile
