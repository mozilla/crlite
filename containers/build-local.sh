#!/bin/bash -xe

VER=0.1

docker build -t crlite:${VER} .. -f Dockerfile
docker build -t crlite:${VER}-rebuild .. -f crlite-rebuild/Dockerfile --build-arg crlite_image=crlite:${VER}
docker build -t crlite:${VER}-fetch .. -f crlite-fetch/Dockerfile --build-arg crlite_image=crlite:${VER}
docker build -t crlite:${VER}-generate .. -f crlite-generate/Dockerfile --build-arg crlite_image=crlite:${VER}
