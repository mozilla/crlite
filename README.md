# CT Map/Reduce Tooling

## Installation

1. Get the [Geo-Mind Lite City GeoIP database (binary)](https://dev.maxmind.com/geoip/geoip2/geolite2/)
1. Grab the most recent Public Suffix List: `wget https://publicsuffix.org/list/effective_tld_names.dat`
1. Install the python dependencies: `pip install -r python/requirements.txt`
1. Build the CT-to-S3 scraper: `go get github.com/jcjones/ct-mapreduce/cmd/ct-fetch`

## Configuration

1. Construct a bucket
1. Make sure you have credentials in ~/.aws/credentials and region in ~/.aws/config
1. Create a configuration file:

```
cat > ~/.ct-fetch.conf <<EOF
# Be sure to replace this path to point to where you got this file
geoipDbPath = /path/to/GeoLite2-City.mmdb
# Update the CT log list as you like, comma-delimited
logList = https://ct.googleapis.com/aviator,https://ct.googleapis.com/rocketeer
# This should be the bucket you create
awsS3Bucket = ctdata
EOF
```

## Populating S3 with CT certificates

```
ct-fetch awsS3Bucket -logList https://ct.googleapis.com/rocketeer --limit 50 -offset 20000000
```
Note: Consider using `--offset X` to start from the `X`th log entry. Also, `--limit Y` will stop after
processing `Y` certificates.


## Processing the CT certificates

Generally, you will run many one Map on each system you're going to use, running on a subset of the
CT data, each producing its own intermediate report file.

```
python python/ct-mapreduce-map.py --s3bucket ctdata --output /tmp/intermediate-report --psl /path/to/effective_tld_names.dat --problems /tmp/problems-intermediate-report
```

## Obtaining Results

Once you collect all the intermediate reports, you collate them:

```
python python/ct-mapreduce-reduce.py --output /tmp/final-report /tmp/intermediate-report ...
```

To get the final summary data, run with only a single input parameter

```
python python/ct-mapreduce-reduce.py --output /tmp/summary-report /tmp/final-report
```

