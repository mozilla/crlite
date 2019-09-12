FROM golang:1.12-stretch as builder
RUN mkdir /build
ADD go /build/
WORKDIR /build
RUN mkdir bin gopath
ENV GOPATH /build/gopath

# Get the current checked-out versions of the CRLite tools
RUN go build -o bin/aggregate-crls /build/cmd/aggregate-crls
RUN go build -o bin/aggregate-known /build/cmd/aggregate-known
# Pull a specific version of ct-mapreduce's ct-fetch
# TODO: Go back to mainline
RUN go get github.com/jcjones/ct-mapreduce/cmd/ct-fetch@firestore

FROM python:3.7-stretch
RUN apt update && apt install -y ca-certificates && \
    apt -y upgrade && apt-get autoremove --purge -y && \
    apt-get -y clean && \
    rm -rf /var/lib/apt/lists/*

RUN adduser --system --home /app appuser

ENV crlite_log /var/log
ENV crlite_processing /processing
ENV crlite_workflow /app/workflow
ENV crlite_bin /app

RUN mkdir /processing && chown appuser /processing && chmod 777 /processing
VOLUME /var/log /processing

COPY requirements.txt /app/
RUN pip3 install -r /app/requirements.txt
COPY --from=builder /build/bin /app/
COPY --from=builder /build/gopath/bin /app/

COPY create_filter_cascade /app/create_filter_cascade
COPY kinto-publisher /app/kinto-publisher
COPY system /app/system
COPY workflow /app/workflow

ENV TINI_VERSION v0.18.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini
ENTRYPOINT ["/tini", "--"]

USER appuser
WORKDIR /app

CMD [ "/bin/bash", "-xc", "/app/system/crlite-fullrun" ]

ENV firestoreProjectId crlite-beta
ENV runForever false
ENV logExpiredEntries false
ENV numThreads 16
ENV cacheSize 64
ENV logList https://ct.googleapis.com/icarus
ENV outputRefreshMs 60000
