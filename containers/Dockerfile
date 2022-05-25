FROM golang:1.18.1-bullseye as go-builder
RUN mkdir /build
ADD go /build/
WORKDIR /build
RUN mkdir bin gopath
ENV GOPATH /build/gopath
RUN go build -o bin/aggregate-crls /build/cmd/aggregate-crls
RUN go build -o bin/aggregate-known /build/cmd/aggregate-known
RUN go build -o bin/ct-fetch /build/cmd/ct-fetch


# rust-cascade with the builder feature needs rust >= 1.61.
FROM rust:1.61-bullseye as rust-builder
RUN mkdir /build

ADD rust-create-cascade /build/rust-create-cascade/
WORKDIR /build/rust-create-cascade
RUN cargo build --release --target-dir /build

ADD rust-query-crlite /build/rust-query-crlite/
WORKDIR /build/rust-query-crlite
RUN cargo build --release --target-dir /build


FROM python:3.8-bullseye
RUN apt update \
    && apt install -y ca-certificates \
    && apt -y upgrade \
    && apt-get autoremove --purge -y \
    && apt-get -y clean \
    && rm -rf /var/lib/apt/lists/*

RUN adduser --system --uid 10001 --group --home /app app

ENV crlite_log /var/log
ENV crlite_processing /processing
ENV crlite_persistent /persistent
ENV crlite_workflow /app/workflow
ENV crlite_bin /app

RUN mkdir /processing && chown app /processing && chmod 777 /processing
VOLUME /var/log /processing /persistent

COPY --from=go-builder /build/bin /app/
COPY --from=rust-builder /build/release/rust-create-cascade /app/
COPY --from=rust-builder /build/release/rust-query-crlite /app/

COPY moz_kinto_publisher /app/moz_kinto_publisher
COPY workflow /app/workflow
COPY containers/scripts /app/scripts
COPY setup.py version.json /app/

RUN pip3 install /app/

ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini
ENTRYPOINT ["/tini", "-g", "--"]

USER app
WORKDIR /app

# For crlite-fetch
ENV runForever true
ENV logExpiredEntries false

EXPOSE 8080/tcp

# For crlite-generate
ENV numThreads 16
ENV cacheSize 64
