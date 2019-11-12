This collection of tools is designed to assemble a cascading
bloom filter containing all TLS certificate revocations, as described
in this [CRLite paper.](http://www.ccs.neu.edu/home/cbw/static/pdf/larisch-oakland17.pdf)

These tools were built from scratch, using the original CRLite research code as a design reference and closely following the documentation in their paper.

## Dependancies
1. `ct-fetch` from [`ct-mapreduce`](https://github.com/jcjones/ct-mapreduce)
1. Python 3
1. Patience; many scripts take several hours even with multiprocessing

## Setup

### Installation

```
go install -u github.com/jcjones/ct-mapreduce/cmd/ct-fetch
go install -u github.com/jcjones/ct-mapreduce/cmd/reprocess-known-certs
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

Then choose either local storage or Firestore cloud storage by setting either
* `firestoreProjectId` [project ID string]
* `certPath` [path string]

If you set `firestoreProjectId`, then choose a firestore instance type:
* `GOOGLE_APPLICATION_CREDENTIALS` [base64-encoded string of the service credentials JSON]
* `FIRESTORE_EMULATOR_HOST` [host]:[port]

If you need to proxy the connection, perhaps via SSH, set the `HTTPS_PROXY` to something like `socks5://localhost:32547/"` as well.

## General Operation

[`system/crlite-fullrun`](https://github.com/mozilla/crlite/tree/master/system/crlite-fullrun) executes a complete "run", syncing with CT and producing a filter. It's configured using a series of environment variables. Generally, this is run from a Docker container.

That script ultimately runs the scripts in [`workflow/`](https://github.com/mozilla/crlite/tree/master/workflow), in order. They can be run independently for fine control.

## Running from a Docker Container

To construct a container, see [`containers/README.md`](https://github.com/mozilla/crlite/tree/master/containers/README.md).

To run with Firestore locally, you'll need the `gcloud` Google Cloud utility's Firestore emulator. For docker, be sure to bind to an accessible address, not just localhost. Port 8403 is just a suggestion:

```
gcloud beta emulators firestore start --host-port="my_ip_address:8403"
```


```
docker run --rm -it \
  -e "FIRESTORE_EMULATOR_HOST=my_ip_address:8403" \
  -e "outputRefreshMs=1000" \
  crlite:0.1
```

To use local disk, set the `certPath` to `/ctdata` and mount that volume in Docker. You should also mount the volume `/processing` to get the output files:
```
docker run --rm -it \
  -e "certPath=/ctdata" \
  -e "outputRefreshMs=1000" \
  --mount type=bind,src=/tmp/ctlite_data,dst=/ctdata \
  --mount type=bind,src=/tmp/crlite_results,dst=/processing \
  crlite:0.1
```


To run in a remote container, such as a Kubernetes pod, you'll need to make sure to set all the environment variables properly, and the container should otherwise work.


## Tools

*`ct-fetch`*
Downloads all CT entries' certificates to a Firestore instance and collects their metadata.

*`reprocess-known-certs`*
Reprocesses all `.pem` files to update the `.pem.meta` and `.pem.known` files. Needed if there's
suspected corruption from crashes of `ct-fetch`.

*`aggregate-crls`*
Obtains all CRLs defined in all CT entries' certificates, verifies them, and collates their results
into `*issuer SKI base64*.revoked` files.

*`aggregate-known`*
Collates all CT entries' unexpired certificates into `*issuer SKI base64*.known` files.


## Planning

If the certificate cohort is 500M, and Firestore costs $0.60 / 1M reads, then `reprocess-known-certs` is $300 to run.


## Credits

* Benton Case for [certificate-revocation-analysis](https://github.com/casebenton/certificate-revocation-analysis)
* JC Jones for [`ct-mapreduce`](https://github.com/jcjones/ct-mapreduce)
* Mark Goodwin for original
  [`filter_cascade`](https://gist.githubusercontent.com/mozmark/c48275e9c07ccca3f8b530b88de6ecde/raw/19152f7f10925379420aa7721319a483273d867d/sample.py)
* The CRLite research team
