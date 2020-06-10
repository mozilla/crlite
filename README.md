This collection of tools is designed to assemble a cascading
bloom filter containing all TLS certificate revocations, as described
in the [CRLite paper](http://www.ccs.neu.edu/home/cbw/static/pdf/larisch-oakland17.pdf).

These tools were built from scratch, using the original CRLite research code as a design reference and closely following the documentation in their paper, however it is a separate implementation, and should still be considered a work in progress, particularly the details of filter generation in [`create_filter_cascade`](https://github.com/mozilla/crlite/tree/main/create_filter_cascade).

For details about CRLite, [Mozilla Security Engineering has a blog post series](https://blog.mozilla.org/security/tag/crlite/), and [this repository has a FAQ](https://github.com/mozilla/crlite/wiki#faq).


## Dependencies
1. `ct-fetch` from [`ct-mapreduce`](https://github.com/jcjones/ct-mapreduce)
1. Python 3
1. Redis 4
1. Kubernetes / Docker
1. Patience


## General Structure

At this point, CRLite is intended to be run in a series of Docker containers, run as differing kinds of jobs:

1. [`containers/crlite-fetch`](https://github.com/mozilla/crlite/tree/main/containers/crlite-fetch), a constantly-running task that downloads from Certificate Transparency logs into Redis and Google Firestore
1. [`containers/crlite-generate`](https://github.com/mozilla/crlite/tree/main/containers/crlite-generate), a periodic (cron) job that produces a CRLite filter from the data in Redis and uploads the artifacts into Google Cloud Storage
1. [`containers/crlite-publish`](https://github.com/mozilla/crlite/tree/main/containers/crlite-generate), a periodic (cron) job that produces a CRLite filter from the data in Redis and uploads the artifacts into Google Cloud Storage

Each of these jobs has a `pod.yaml` intended for use in Kubernetes.

There are scripts in [`containers/`](https://github.com/mozilla/crlite/tree/main/containers) to build Docker images both using Google Cloud's builder and locally with Docker, see `build-gcp.sh` and `build-local.sh`. They make assumptions about the `PROJECT_ID` which will need to change, but PRs are welcome.


### Storage
Storage consists of these parts:

1. Redis, e.g. Google Cloud Memorystore, for certificate metadata (CRL DPs, serial numbers, expirations, issuers), used in filter generation.
1. Google Cloud Storage, for storage of the artifacts when a job is completed.
1. A local persistent disk, for persistent storage of downloaded CRLs. This is defined in [`containers/crl-storage-claim.yaml`](https://github.com/mozilla/crlite/blob/main/containers/crl-storage-claim.yaml).


### Information Flow

This tooling monitors Certificate Transparency logs and, upon secheduled execution, `crlite-generate` produces a new filter and uploads it to Cloud Storage.

![Information flow](docs/figure1-information_flow.png)

The process for producing a CRLite filter, is run by [`system/crlite-fullrun`](https://github.com/mozilla/crlite/blob/main/system/crlite-fullrun), which is described in block form in this diagram:

![Process for building a CRLite Bloom filter](docs/figure2-filter_process.png)


The output Bloom filter cascade is built by the Python [`mozilla/filter-cascade`](https://github.com/mozilla/filter-cascade) tool and then read in Firefox by the Rust [`mozilla/rust-cascade`](https://github.com/mozilla/rust-cascade) package.

For complete details of the filter construction see Section III.B of the [CRLite paper](http://www.ccs.neu.edu/home/cbw/static/pdf/larisch-oakland17.pdf).

![Structure of the CRLite Bloom filter cascade](docs/figure3-filter_structure.png)

The keys used into the CRLite data structure consist of the SHA256 digest of the issuer's `Subject Public Key Information` field in DER-encoded form, followed by the the certificate's serial number, unmodified, in DER-encoded form.

![Structure of Certificate Identifiers](docs/figure4-certificate_identifier.png)


## Local Installation

It's possible to run the tools locally, though you will need local instances of Redis and Firestore. First, install the tools and their dependnecnies

```sh
go install -u github.com/jcjones/ct-mapreduce/cmd/ct-fetch
go install -u github.com/mozilla/crlite/go/cmd/aggregate-crls
go install -u github.com/mozilla/crlite/go/cmd/aggregate-known

pipenv install
```


### Configuration

You can configure via a config file, or use environment variables.

To use a configuration file,  `~/.ct-fetch.ini` (or any file selected on the CLI using `-config`), construct it as so:

```
certPath = /ct
numThreads = 16
cacheSize = 128
```


#### Parameters

You'll want to set a collection of configuration parameters:

* `runForever` [true/false]
* `logExpiredEntries` [true/false]
* `numThreads` 16
* `cacheSize` [number of cache entries. An individual entry contains an issuer-day's worth of serial numbers, which could be as much as 64 MB of RAM, but is generally closer to 1 MB.]
* `outputRefreshMs` [milliseconds]

The log list is all the logs you want to sync, comma separated, as URLs:
* `logList` https://ct.googleapis.com/icarus, https://oak.ct.letsencrypt.org/2021/

To get all current ones from
[certificate-transparency.org](https://certificate-transparency.org/):
```
echo "logList = $(setup/list_all_active_ct_logs)" >> ~/.ct-fetch.ini
```

If running forever, set the delay on polling for new updates, per log. This will have some jitter added:
* `pollingDelay` [minutes]

If not running forever, you can give limits or slice up CT log data:
* `limit` [uint]
* `offset` [uint]

You'll also need to configure credentials used for Google Cloud Storage:
* `GOOGLE_APPLICATION_CREDENTIALS` [base64-encoded string of the service credentials JSON]

If you need to proxy the connection, perhaps via SSH, set the `HTTPS_PROXY` to something like `socks5://localhost:32547/"` as well.


### General Operation

[`containers/build-local.sh`](https://github.com/mozilla/crlite/tree/main/containers/build-local.sh) produces the Docker containers locally.

[`test-via-docker.sh`](https://github.com/mozilla/crlite/tree/main/test-via-docker.sh) executes a complete "run", syncing with CT and producing a filter. It's configured using a series of environment variables.


### Starting the Local Dependencies

Redis can be provided in a variety of ways, easiest is probably the Redis docker distribution. For whatever reason, I have the
best luck remapping ports to make it run on 6379:
```sh
docker run -p 6379:7000 redis:4 --port 7000
```


## Running from a Docker Container

To construct a container, see [`containers/README.md`](https://github.com/mozilla/crlite/tree/main/containers/README.md).

The crlite-fetch container runs forever, fetching CT updates:

```sh
docker run --rm -it \
  -e "FIRESTORE_EMULATOR_HOST=my_ip_address:8403" \
  -e "outputRefreshMs=1000" \
  crlite:0.1-fetch
```

The crlite-generate container constructs a new filter. To use local disk, set the `certPath` to `/ctdata` and mount that volume in Docker. You should also mount the volume `/processing` to get the output files:

```sh
docker run --rm -it \
  -e "certPath=/ctdata" \
  -e "outputRefreshMs=1000" \
  --mount type=bind,src=/tmp/ctlite_data,dst=/ctdata \
  --mount type=bind,src=/tmp/crlite_results,dst=/processing \
  crlite:0.1-generate
```

See the [`test-via-docker.sh`](https://github.com/mozilla/crlite/blob/main/test-via-docker.sh) for an example.

To run in a remote container, such as a Kubernetes pod, you'll need to make sure to set all the environment variables properly, and the container should otherwise work. See [`containers/crlite-config.properties.example`](https://github.com/mozilla/crlite/blob/main/containers/crlite-config.properties.example) for an example of the Kubernetes environment that can be imported using `kubectl create configmap`, see the `containers` README.md for details.


## Tools

*`ct-fetch`*
Downloads all CT entries' certificates to a Firestore instance and collects their metadata.

*`aggregate-crls`*
Obtains all CRLs defined in all CT entries' certificates, verifies them, and collates their results
into `*issuer SKI base64*.revoked` files.

*`aggregate-known`*
Collates all CT entries' unexpired certificates into `*issuer SKI base64*.known` files.



## Credits

* Benton Case for [certificate-revocation-analysis](https://github.com/casebenton/certificate-revocation-analysis)
* Mark Goodwin for the original Python [`filter_cascade`](https://gist.githubusercontent.com/mozmark/c48275e9c07ccca3f8b530b88de6ecde/raw/19152f7f10925379420aa7721319a483273d867d/sample.py)
* Dana Keeler and Mark Goodwin together for the Rust [`rust-cascade`](https://github.com/mozilla/rust-cascade)
* The CRLite research team: James Larsich, David Choffnes, Dave Levin, Bruce M. Maggs, Alan Mislove, and Christo Wilson
