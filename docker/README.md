docker run --rm -it \
  --mount type=bind,source=/tmp,target=/var/log \
  --mount type=bind,source=/Users/jcjones/ct/data,target=/ctdata \
  --mount type=bind,source=/Users/jcjones/ct/config,target=/config,readonly \
  --mount type=bind,source=/Users/jcjones/ct/processing,target=/processing \
  crlite-go:0.1 ./ct-fetch -config /config/ct-fetch.ini -log_dir /var/log

docker run --rm -it \
  crlite-go:0.1 ./get-mozilla-issuers

docker run --rm -it \
  --mount type=bind,source=/tmp,target=/var/log \
  --mount type=bind,source=/Users/jcjones/ct/data,target=/ctdata \
  --mount type=bind,source=/Users/jcjones/ct/config,target=/config,readonly \
  --mount type=bind,source=/Users/jcjones/ct/processing,target=/processing \
  crlite-py:0.1 python3 kinto-publisher/main.py
