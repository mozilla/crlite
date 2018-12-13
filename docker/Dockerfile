FROM golang:1.11-stretch as builder
RUN mkdir /build
ADD go /build/
WORKDIR /build
RUN mkdir bin
RUN go build -o bin/aggregate-crls /build/cmd/aggregate-crls
RUN go build -o bin/aggregate-known /build/cmd/aggregate-known
RUN go build -o bin/get-mozilla-issuers /build/cmd/get-mozilla-issuers

FROM alpine
RUN adduser -S -D -H -h /app appuser
USER appuser
COPY --from=builder /build/bin /app/
WORKDIR /app
CMD ["./get-mozilla-issuers"]