# rust-query-crlite

A standalone tool for querying Firefox's CRLite data.

# Example usage

By default rust-query-crlite will look for CRLite artifacts in `./crlite_db`. It will not download new artifacts.

```console
$ rust-query-crlite https github.com
ERROR - No CRLite filters found. All results will indicate NotCovered. Use --update to download filters.
INFO - github.com NotCovered
```

Pass `--update prod` to get the latest CRLite filters from the
[production instance](https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/cert-revocations/records)
 of Firefox Remote Settings.

```console
$ rust-query-crlite --update prod https github.com
INFO - Loaded 49 CRLite filter(s), most recent was downloaded: 0 hours ago
INFO - github.com Good
```

Subsequent queries can be made without updating the database.
```console
$ rust-query-crlite https mozilla.org
INFO - Loaded 49 CRLite filter(s), most recent was downloaded: 4 hours ago
INFO - mozilla.org Good
```

Pass `-v` or `-vv` to get additional diagnostic output.

```console
$ rust-query-crlite -v https github.com
INFO - Loaded 49 CRLite filter(s), most recent was downloaded: 0 hours ago
DEBUG - Loaded certificate from github.com
DEBUG - Issuer DN: C=GB, ST=Greater Manchester, L=Salford, O=Sectigo Limited, CN=Sectigo ECC Domain Validation Secure Server CA
DEBUG - Subject DN: CN=github.com
DEBUG - Serial number: 00ab6686b5627be80596821330128649f5
DEBUG - Issuer SPKI hash: 6YBE8kK4d5J1qu1wEjyoKqzEIvyRY5HyM_NB2wKdcZo=
INFO - github.com Good
```

Use the `x509` subcommand to query a (DER or PEM encoded) certificate directly.

```console
$ rust-query-crlite x509 16526155701.crt
INFO - Loaded 49 CRLite filter(s), most recent was downloaded: 0 hours ago
INFO - /home/john/Downloads/16526155701.crt Good
```

Or the `crtsh` subcommand to query a certificate by its [crt.sh](https://crt.sh) id.

```console
$ rust-query-crlite crtsh 16526155701
INFO - Loaded 49 CRLite filter(s), most recent was downloaded: 0 hours ago
INFO - 16526155701 Good
```

There are multiple CRLite "channels" in Firefox Remote Settings that offer different size / coverage / latency tradeoffs.

The `default` channel includes all revocations:
```console
$ rust-query-crlite --update prod --channel default https revoked-isrgrootx2.letsencrypt.org
INFO - Loaded 49 CRLite filter(s), most recent was downloaded: 0 hours ago
INFO - revoked-isrgrootx2.letsencrypt.org Revoked
```

The `compat` channel only includes revocations with the `keyCompromise`, `cessationOfOperation`, and `privilegeWithdrawn` reason codes.
```
$ rust-query-crlite --update prod --channel compat https revoked-isrgrootx2.letsencrypt.org
INFO - Loaded 49 CRLite filter(s), most recent was downloaded: 0 hours ago
INFO - revoked-isrgrootx2.letsencrypt.org Good
```

The database directory can be set with the `-d` flag. To query CRLite data from a Firefox profile you can pass `-d <path to profile>/security_state`. However, it's best to work on a copy of your Firefox profile's state, as rust-query-crlite uses the database directory to store some additional files that Firefox does not need.

```console
$ cp -r <profile>/security_state/ /tmp
$ rust-query-crlite -d /tmp/security_state/ https github.com
INFO - Loaded 49 CRLite filter(s), most recent was downloaded: 0 hours ago
INFO - github.com Good
```
