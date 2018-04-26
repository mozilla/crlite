from ct_fetch_utils import processCTData
from settings import CT_FETCH_DATA_DIR, CRL_SERVERS_FILENAME, CERTS_OUTFILE


crl_outfile = open(CRL_SERVERS_FILENAME, "w", 1)
certs_outfile = open(CERTS_OUTFILE, "w", 1)

print("processing certificates into %s and %s" % (
    CERTS_OUTFILE, CRL_SERVERS_FILENAME
))
processCTData(
    CT_FETCH_DATA_DIR,
    crl_outfile,
    certs_outfile
)
