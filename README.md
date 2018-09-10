# CT Map/Reduce Tooling

## Installation

1. Get the [Geo-Mind Lite City GeoIP database (binary)](https://dev.maxmind.com/geoip/geoip2/geolite2/)
1. Grab the most recent Public Suffix List: `wget https://publicsuffix.org/list/effective_tld_names.dat`
1. Install the python dependencies: `pip install -r python/requirements.txt`
1. Build the CT-to-Disk scraper: `go get github.com/jcjones/ct-mapreduce/cmd/ct-fetch`

## Configuration

1. Create a configuration file:

```
cat > ~/.ct-fetch.conf <<EOF
# Available directives:
#
# certPath = Path under which to store full DER-encoded certificates
# issuerCNFilter = Prefixes to match for CNs for permitted issuers, comma delimited
# runForever = Run forever, pausing `pollingDelay` between runs
# pollingDelay = Wait this many minutes between polls
# logExpiredEntries = Add expired entries to the database
# numThreads = Use this many threads per CPU
# logList = URLs of the CT Logs, comma delimited
#
# Examples
#
# Only accept certificates for Let's Encrypt's intermediates or the ISRG roots
issuerCNFilter = Let's Encrypt, ISRG
# Update the CT log list as you like, comma-delimited. Not currently tested with more than one log.
logList = https://ct.googleapis.com/icarus
# A path with plenty of disk space
certPath = /ct
# Choose if this should complete when it catches up to the CT logs, or be a daemon
runForever = false
EOF
```

## Populating your disk with CT certificates

```
ct-fetch -config ~/.ct-fetch.conf
```
Note: Consider using `--offset X` to start from the `X`th log entry. Also, `--limit Y` will stop after
processing `Y` certificates.


## Processing the CT certificates

Generally, you will run Map on each system you're going to use, running on a subset of the
CT data, each producing its own intermediate report file. Right now Map assumes a single system,
but does use all available cores.

```
python python/ct-mapreduce-map.py --path /ct --psl /path/to/effective_tld_names.dat
```

## Obtaining A Day's Results

Once you collect all the intermediate reports, you collate them:

```
python python/ct-mapreduce-reduce.py --expiredate 2017-07-09 --output /ct/reduction-2017-07-09.out --path /ct
```

## Producing Readable Results
To get the final summary data in text form, run with only a single input parameter

```
python python/ct-mapreduce-reduce.py /ct/reduction-2017-07-09.out
```

Alternatively, to write the summary data to a SQLite DB, process that final summary data this way:
```
python python/ct-mapreduce-reduce-to-storage.py --today 2017-07-09 --db ~/sqlite.db /ct/reduction-2017-07-09.out
```

