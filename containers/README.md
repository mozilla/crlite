# Local

See `./build-local.sh`

Basic build:
```
docker build -t crlite:0.1 .. -f Dockerfile
```

To run the whole tool:

```
docker run --rm -it \
  --mount type=bind,source=/tmp/dockerlog,target=/var/log \
  --mount type=bind,source=/Users/jcjones/ct/data,target=/ctdata \
  --mount type=bind,source=/Users/jcjones/ct/config,target=/config,readonly \
  --mount type=bind,source=/Users/jcjones/ct/processing,target=/processing \
  -e "crlite_refresh_ms=1000" \
  -e "KINTO_AUTH_USER=user" \
  -e "KINTO_AUTH_PASSWORD=secretString" \
  crlite:0.1
```

If you need to proxy the connection, set the `HTTPS_PROXY` like  `-e "HTTPS_PROXY=socks5://localhost:32547/"` as well.


# Remote via Google Cloud:

See `./build-gcp.sh`

Basic build:

```
gcloud config set project crlite-beta
gcloud builds submit --config containers/cloudbuild.yaml ..
```


# Kubernetes

```
```
