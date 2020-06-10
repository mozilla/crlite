# Local

See `./build-local.sh`

Basic build:
```
docker build -t crlite:0.1 .. -f Dockerfile
```

To run the tools, you'll need Redis 4+:

```
docker run --rm -it -p 6379:7000 \
  redis:4 --port 7000
```

Then you can execute the docker container, setting any environment vars you want:

```
docker run --rm -it \
  -e "redisHost=10.0.0.115:6379" \
  -e "outputRefreshMs=1000" \
  crlite:0.1
```

See the Running section for more environment variables.

# Remote via Google Cloud:

See `./build-gcp.sh`

Basic build:

```
gcloud config set project crlite-beta
gcloud builds submit --config containers/cloudbuild.yaml ..
```

# Deploying

## Set up configuration
customize `crlite-config.properties.example` to `crlite-config.properties`

```
kubectl delete configmap crlite-config && \
      kubectl create configmap crlite-config \
      --from-env-file=crlite-config.properties
```

## Create CRL storage
```
kubectl create -f crl-storage-claim.yaml
```

## Always-on Deployment
`kubectl create -f crlite-fetch`

## Periodic jobs

### Filter generation
`kubectl create -f crlite-generate`

### Filter publication
`kubectl create -f crlite-publish`
