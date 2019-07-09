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
  -e "crlite_refresh_ms=1000"
  crlite:0.1
```


# Remote via Google Cloud:

See `./build-gcp.sh`

Basic build:

```
gcloud config set project crlite-beta
gcloud builds submit --config containers/cloudbuild.yaml ..
```
