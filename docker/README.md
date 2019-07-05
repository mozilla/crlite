# Local

docker build -t crlite:0.1 .. -f Dockerfile

docker run --rm -it \
  --mount type=bind,source=/tmp/dockerlog,target=/var/log \
  --mount type=bind,source=/Users/jcjones/ct/data,target=/ctdata \
  --mount type=bind,source=/Users/jcjones/ct/config,target=/config,readonly \
  --mount type=bind,source=/Users/jcjones/ct/processing,target=/processing \
  crlite:0.1



# Remote

gcloud config set project crlite-beta
gcloud builds submit --config docker/cloudbuild.yaml .
