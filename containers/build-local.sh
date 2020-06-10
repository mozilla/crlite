#!/bin/bash -xe

VER=0.1
CT_MAPREDUCE_VER=v1.0.5

docker build -t crlite:${VER} .. -f Dockerfile --build-arg ct_mapreduce_ver=${CT_MAPREDUCE_VER}
docker build -t crlite:${VER}-rebuild .. -f crlite-rebuild/Dockerfile --build-arg crlite_image=crlite:${VER}
docker build -t crlite:${VER}-fetch .. -f crlite-fetch/Dockerfile --build-arg crlite_image=crlite:${VER}
docker build -t crlite:${VER}-generate .. -f crlite-generate/Dockerfile --build-arg crlite_image=crlite:${VER}
docker build -t crlite:${VER}-publish .. -f crlite-publish/Dockerfile --build-arg crlite_image=crlite:${VER}
