# Python Standard Library
from datetime import datetime
import json

# Local modules
from filter_cascade import FilterCascade


mlbf_file_version = datetime.utcnow().strftime('%Y%m%d')
MLBF_FILENAME = 'moz-crlite-mlbf-%s' % mlbf_file_version
MLBF_FILE_FORMAT_VERSION = 1
NONREVOKED_CERTS_FILENAME = '../get_CRL_revocations/final_crl_nonrevoked.json'
REVOKED_CERTS_FILENAME = '../get_CRL_revocations/final_crl_revoked.json'


def bufcount(filename):
    f = open(filename)
    lines = 0
    buf_size = 1024 * 1024
    read_f = f.read

    buf = read_f(buf_size)
    while buf:
        lines += buf.count('\n')
        buf = read_f(buf_size)

    return lines


print("Turning %s nonrevoked and %s revoked certs into %s" % (
    bufcount(NONREVOKED_CERTS_FILENAME), bufcount(REVOKED_CERTS_FILENAME),
    MLBF_FILENAME
))

nonrevoked_certs = []
revoked_certs = []

nonrevoked_certs_file = open(NONREVOKED_CERTS_FILENAME)
revoked_certs_file = open(REVOKED_CERTS_FILENAME)

for line in nonrevoked_certs_file:
    cert = json.loads(line)
    nonrevoked_certs.append(cert['issuer']['organization'] + str(cert['serial_number']))

for line in revoked_certs_file:
    cert = json.loads(line)
    revoked_certs.append(cert['issuer']['organization'] + str(cert['serial_number']))


cascade = FilterCascade(120000, 1.3, 0.20, 1)
cascade.initialize(revoked_certs, nonrevoked_certs)
cascade.check(revoked_certs, nonrevoked_certs)

print("Filter Cascade:\n%s" % cascade)

print("This filter cascade uses %d layers and %d bits" % (
    cascade.layerCount(),
    cascade.bitCount())
)

print("Writing to file %s" % MLBF_FILENAME)

mlbf_file = open(MLBF_FILENAME, 'wb')

cascade.tofile(mlbf_file)
