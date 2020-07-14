#!/bin/bash -xe

VER=staging
CT_MAPREDUCE_VER=v1.0.10

docker build -t crlite:${VER} .. -f Dockerfile --build-arg ct_mapreduce_ver=${CT_MAPREDUCE_VER}
