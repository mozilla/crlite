#!/bin/bash -e

docker build -t crlite-go:0.1 .. -f crlite-go/Dockerfile

docker build -t crlite-py:0.1 .. -f crlite-py/Dockerfile
