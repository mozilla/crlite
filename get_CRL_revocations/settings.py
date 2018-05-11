from decouple import config


CT_FETCH_DATA_DIR = config('CT_FETCH_DATA_DIR', default='/Users/lcrouch/ct')
CRL_SERVERS_FILENAME = config(
    'CRL_SERVERS_FILENAME', default='CRL_servers.txt'
)
CERTS_OUTFILE = config('CERTS_OUTFILE', default='certs_using_CRL.json')
ALL_CRLS_DIR = config('ALL_CRLS_DIR', default='all_CRLs')
COMBINED_CRL_OUTFILE = config('COMBINED_CURL_OUTFILE', default='mega_CRL.json')
FINAL_REVOKED_CERTS_FILE = config(
    'FINAL_REVOKED_CERTS_FILE', default='final_crl_revoked.json'
)
FINAL_NONREVOKED_CERTS_FILE = config(
    'FINAL_NONREVOKED_CERTS_FILE', default='final_crl_nonrevoked.json'
)
