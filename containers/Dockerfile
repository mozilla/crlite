FROM golang:1.13-buster as builder
RUN mkdir /build
ADD go /build/
WORKDIR /build
RUN mkdir bin gopath
ENV GOPATH /build/gopath

ARG ct_mapreduce_ver=v1.0.10

# Get the current checked-out versions of the CRLite tools
RUN go build -o bin/aggregate-crls /build/cmd/aggregate-crls
RUN go build -o bin/aggregate-known /build/cmd/aggregate-known
RUN go build -o bin/ct-fetch /build/cmd/ct-fetch

FROM python:3.8-buster
RUN apt update && apt install -y ca-certificates && \
    apt -y upgrade && apt-get autoremove --purge -y && \
    apt-get -y clean && \
    rm -rf /var/lib/apt/lists/*

RUN adduser --system --uid 10001 --group --home /app app

ENV crlite_log /var/log
ENV crlite_processing /processing
ENV crlite_persistent /persistent
ENV crlite_workflow /app/workflow
ENV crlite_bin /app

RUN mkdir /processing && chown app /processing && chmod 777 /processing
VOLUME /var/log /processing /persistent

COPY --from=builder /build/bin /app/

COPY moz_crlite_lib /app/moz_crlite_lib
COPY create_filter_cascade /app/create_filter_cascade
COPY moz_kinto_publisher /app/moz_kinto_publisher
COPY workflow /app/workflow
COPY containers/scripts /app/scripts
COPY setup.py version.json /app/
RUN pip3 install /app/moz_crlite_lib/ /app/

ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini
ENTRYPOINT ["/tini", "-g", "--"]

USER app
WORKDIR /app

ENV outputRefreshMs 60000

# For crlite-fetch
ENV runForever true
ENV logExpiredEntries false
ENV logList https://ct.googleapis.com/icarus

EXPOSE 8080/tcp

# For crlite-generate
ENV numThreads 16
ENV cacheSize 64
