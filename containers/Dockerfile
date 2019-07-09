FROM golang:1.12-stretch as builder
RUN mkdir /build
ADD go /build/
WORKDIR /build
RUN mkdir bin gopath
ENV GOPATH /build/gopath

# Get the current checked-out versions of the CRLite tools
RUN go build -o bin/aggregate-crls /build/cmd/aggregate-crls
RUN go build -o bin/aggregate-known /build/cmd/aggregate-known
RUN go build -o bin/get-mozilla-issuers /build/cmd/get-mozilla-issuers
# Pull a specific version of ct-mapreduce's ct-fetch
RUN go get github.com/jcjones/ct-mapreduce/cmd/ct-fetch@v1.0.2

FROM python:3.7-stretch
RUN apt update && apt install -y ca-certificates && \
    apt -y upgrade && apt-get autoremove --purge -y && \
    apt-get -y clean && \
    rm -rf /var/lib/apt/lists/*

RUN adduser --system --home /app appuser

VOLUME /var/log /ctdata /processing /config
ENV crlite_log /var/log
ENV crlite_ctdata /ctdata
ENV crlite_processing /processing
ENV crlite_config /config/ct-fetch.ini
ENV crlite_workflow /app/workflow
ENV crlite_bin /app
ENV crlite_refresh_ms 60000

COPY requirements.txt /app/
RUN pip3 install -r /app/requirements.txt
COPY --from=builder /build/bin /app/
COPY --from=builder /build/gopath/bin /app/

USER appuser
COPY create_filter_cascade /app/create_filter_cascade
COPY kinto-publisher /app/kinto-publisher
COPY system /app/system
COPY workflow /app/workflow

WORKDIR /app

CMD /app/system/crlite-fullrun
