FROM golang:1.11-stretch as builder
RUN mkdir /build
ADD go /build/
WORKDIR /build
RUN mkdir bin
RUN go build -o bin/aggregate-crls /build/cmd/aggregate-crls
RUN go build -o bin/aggregate-known /build/cmd/aggregate-known
RUN go build -o bin/get-mozilla-issuers /build/cmd/get-mozilla-issuers
RUN go build -o bin/ct-fetch github.com/jcjones/ct-mapreduce/cmd/ct-fetch

#FROM alpine
FROM debian:stretch-slim
RUN apt update && apt install -y ca-certificates && apt -y upgrade
RUN adduser --system --home /app appuser
USER appuser
COPY --from=builder /build/bin /app/
WORKDIR /app
CMD ["./get-mozilla-issuers"]

VOLUME /var/log /ctdata /processing /config