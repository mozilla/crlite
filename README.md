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
go install -u github.com/mozilla/crlite/go/cmd/get-mozilla-issuers

pip3 install -r requirements.txt
```

### Configuration

Configure a `~/.ct-fetch.ini`
```
certPath = /ct
numThreads = 16
cacheSize = 2048
```

Be sure to add the list of CT logs you wish to fetch. To get all current ones from
[certificate-transparency.org](https://certificate-transparency.org/):
```
echo "logList = $(setup/list_all_active_ct_logs)" >> ~/.ct-fetch.ini
```

## General Operation

Run the scripts in [`workflow/`](https://github.com/mozilla/crlite/tree/master/workflow)
in order, each time step desired.

## Tools

*`ct-fetch`*
Downloads all CT entries' certificates to `certPath` and collects their metadata. The results are
collated into `*certPath config*/*expiration date*/*issuer SKI base64*.pem{.known/.meta}`

*`reprocess-known-certs`*
Reprocesses all `.pem` files to update the `.pem.meta` and `.pem.known` files. Needed if there's
suspected corruption from crashes of `ct-fetch`.

*`aggregate-crls`*
Obtains all CRLs defined in all CT entries' certificates, verifies them, and collates their results
into `*issuer SKI base64*.revoked` files.

*`aggregate-known`*
Collates all CT entries' unexpired certificates into `*issuer SKI base64*.known` files.

*`get-mozilla-issuers`*
Produces a JSON-formatted list of all `*issuer SKI base64*` identifiers in the Mozilla root program.
The `aggregate-crls` and `aggregate-known` tools use that information, it can also be useful for
other scripts, hence this utility.

## Credits

* Benton Case for [certificate-revocation-analysis](https://github.com/casebenton/certificate-revocation-analysis)
* JC Jones for [`ct-mapreduce`](https://github.com/jcjones/ct-mapreduce)
* Mark Goodwin for original
  [`filter_cascade`](https://gist.githubusercontent.com/mozmark/c48275e9c07ccca3f8b530b88de6ecde/raw/19152f7f10925379420aa7721319a483273d867d/sample.py)
* The CRLite research team
