[![Build Status](https://circleci.com/gh/mozilla/crlite.svg?style=shield)](https://circleci.com/gh/mozilla/crlite)
![Docker Version](https://img.shields.io/docker/v/mozilla/crlite)

CRLite pushes the full set of WebPKI certificate revocations to Firefox clients for private querying. It replaces [OCSP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol) for most browser TLS connections and speeds up connection time without compromising on security. The system was originally proposed at [IEEE S&P 2017](http://www.ccs.neu.edu/home/cbw/static/pdf/larisch-oakland17.pdf). Significant improvements to the underlying datastructure were presented at [RWC 2022](https://rwc.iacr.org/2022/program.php#abstract-talk-39), [RWC 2025](https://rwc.iacr.org/2025/program.php#abstract-talk-42), and [IEEE S&P 2025](https://research.mozilla.org/files/2025/04/clubcards_for_the_webpki.pdf). The implementation here uses the *Clubcard* data structure described in these later works.

For more details about CRLite, [Mozilla Security Engineering has a blog post series](https://blog.mozilla.org/security/tag/crlite/), and [this repository has a FAQ](https://github.com/mozilla/crlite/wiki#faq).

This repository contains all of the tools needed to produce Clubcards encoding the WebPKI revocation set. It also includes an end-user tool for querying Firefox's CRLite data: [rust-query-crlite](https://github.com/mozilla/crlite/tree/main/rust-query-crlite).

## General Structure

CRLite is designed to run in Kubernetes, with the following services:

1. [`containers/crlite-fetch`](https://github.com/mozilla/crlite/tree/main/containers/crlite-fetch), a constantly-running task that fetches certificate metadata from Certificate Transparency logs and stores that metadata in a Redis cache.
1. [`containers/crlite-generate`](https://github.com/mozilla/crlite/tree/main/containers/crlite-generate), a cron job that moves certificate metadata from the Redis cache to persistent storage, fetches CRLs, creates Clubcards, and uploads artifacts to Google Cloud Storage.
1. [`containers/crlite-publish`](https://github.com/mozilla/crlite/tree/main/containers/crlite-publish), a cron job that publishes newly generated Clubcards through Firefox Remote Settings.
1. [`containers/crlite-signoff`](https://github.com/mozilla/crlite/tree/main/containers/crlite-signoff), a cron job that performs some basic consistency checks and signs off on the records produced by `crlite-publish`.

There are scripts in [`containers/`](https://github.com/mozilla/crlite/tree/main/containers) to build Docker images both using Docker. There are also builds at Docker Hub in the [`mozilla/crlite`](https://hub.docker.com/r/mozilla/crlite) project.

### Storage
Storage consists of these parts:

1. Redis for initial ingestion of the certificate metadata (serial numbers, expirations, issuers) used in filter generation.
1. A local disk for persistent storage of certificate metadata and CRLs.
1. Google Cloud Storage for storage of the artifacts when a job is completed.

### Information Flow

This tooling monitors Certificate Transparency logs and, upon secheduled execution, `crlite-generate` produces a new filter and uploads it to Cloud Storage.

![Information flow](docs/figure1-information_flow.png)

Clubcards are built using the [rust-create-cascade](https://github.com/mozilla/crlite/tree/main/rust-create-cascade) tool and then read in Firefox by the [`mozilla/clubcard-crlite`](https://github.com/mozilla/clubcard-crlite) package.

## Local Installation

It's possible to run the tools locally. First, install the tools and their dependencies

```sh
go install -u github.com/mozilla/crlite/go/cmd/ct-fetch
go install -u github.com/mozilla/crlite/go/cmd/aggregate-crls
go install -u github.com/mozilla/crlite/go/cmd/aggregate-known
```

### Configuration

You can configure via environment variables, or via a config file. To use a configuration file `~/.ct-fetch.ini` (or any file selected on the CLI using `-config`), construct it as so:

```
certPath=/tmp/certdb/
remoteSettingsURL=""
ctLogMetadata=[...]
runForever = true
```

Set the `ctLogMetadata` variable equal to the contents of the [ct-logs](https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/ct-logs/records) collection in Firefox Remote Settings (without newline characters). For testing you can trim this to a single CT log. Other configuration options are described in [go/config/config.go](https://github.com/mozilla/crlite/blob/0b23eb142ca0627f33a19b94302df9c13bd14ad3/go/config/config.go#L200-L224).

### General Operation

[`containers/build-local.sh`](https://github.com/mozilla/crlite/tree/main/containers/build-local.sh) produces the Docker containers locally.

[`test-via-docker.sh`](https://github.com/mozilla/crlite/tree/main/test-via-docker.sh) executes a complete "run", syncing with CT and producing a filter. It's configured using a series of environment variables.

### Starting the Redis cache

Redis can be provided in a variety of ways, easiest is probably the Redis docker distribution. For whatever reason, I have the
best luck remapping ports to make it run on 6379:
```sh
docker run -p 6379:7000 redis:4 --port 7000
```

## Tools

*`ct-fetch`*
Downloads all CT entry issuer-serial pairs, and associated metadata, to the Redis cache.

*`aggregate-crls`*
Obtains all CRLs disclosed to [CCADB](https://ccadb-public.secure.force.com/mozilla/MozillaIntermediateCertsCSVReport), verifies them, and lists their contents into `*issuer SKI base64*.revoked` files.

*`aggregate-known`*
Moves certificate metadata from the Redis cache to persistent storage. Lists all known unexpired certificates into `*issuer SKI base64*.known` files.

## Credits

* The CRLite research team: James Larsich, David Choffnes, Dave Levin, Bruce M. Maggs, Alan Mislove, and Christo Wilson.
* Benton Case for [certificate-revocation-analysis](https://github.com/casebenton/certificate-revocation-analysis), which kicked off this effort.
* Mark Goodwin for the original Python [`filter_cascade`](https://gist.githubusercontent.com/mozmark/c48275e9c07ccca3f8b530b88de6ecde/raw/19152f7f10925379420aa7721319a483273d867d/sample.py) and the [`filter-cascade`](https://github.com/mozilla/filter-cascade) project.
* Dana Keeler and Mark Goodwin together for the Rust [`rust-cascade`](https://github.com/mozilla/rust-cascade).
