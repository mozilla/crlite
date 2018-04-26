
import json

from settings import (
    CERTS_OUTFILE, COMBINED_CRL_OUTFILE,
    FINAL_NONREVOKED_CERTS_FILE, FINAL_REVOKED_CERTS_FILE
)

final_revoked_certs_file = open(FINAL_REVOKED_CERTS_FILE, 'w', 1)
final_nonrevoked_certs_file = open(FINAL_NONREVOKED_CERTS_FILE, 'w', 1)


def isRevoked(megaCRL_org, megaCRL_CN, org, CN, serial):
    if org in megaCRL_org:
        if serial in megaCRL_org[org]:
            return True
    if CN in megaCRL_CN:
        if serial in megaCRL_CN[CN]:
            return True
    return False


def buildDict():
    megaCRL_CN = {}
    megaCRL_org = {}
    crlFile = open(COMBINED_CRL_OUTFILE, 'r')
    for line in crlFile:
        parsed = json.loads(line)
        issuer = parsed['crl_issuer']
        for entry in issuer:
            if entry[0] == "O":
                org = entry[1].replace(" ", "_")
                if org not in megaCRL_org:
                    megaCRL_org[org] = []
                for serial in parsed['cert_serials']:
                    megaCRL_org[org].append(int(serial, 16))
            if entry[0] == "CN":
                CN = entry[1].replace(" ", "_")
                if CN not in megaCRL_CN:
                    megaCRL_CN[CN] = []
                for serial in parsed['cert_serials']:
                    megaCRL_CN[CN].append(int(serial, 16))
    return megaCRL_CN, megaCRL_org


if __name__ == '__main__':
    print('Using %s and %s to create %s...' % (
        CERTS_OUTFILE, COMBINED_CRL_OUTFILE, FINAL_REVOKED_CERTS_FILE
    ))
    megaCRL_CN, megaCRL_org = buildDict()

    ctr = 0
    for cert_line in open(CERTS_OUTFILE, 'r'):
        ctr += 1
        if(ctr % 10000 == 0):
            print(str(ctr) + " certificates processed")
        try:
            cert = json.loads(cert_line)
            issuer = cert['issuer']
            serial = cert['serial_number']
            subject = cert['subject']
            public_key = cert['public_key_bytes']
        except:
            print("Error getting/loading/parsing %s" % cert)
            continue  # skip to next certificate
        org = 'unknown'
        if 'organization' in issuer:
            org = issuer['organization']
        CN = 'unknown'
        if 'common_name' in issuer:
            CN = issuer['common_name']
        if (
            (org in megaCRL_org and serial in megaCRL_org[org]) or
            (CN in megaCRL_CN and serial in megaCRL_CN[CN])
        ):
            final_revoked_certs_file.write(json.dumps(cert) + '\n')
        else:
            final_nonrevoked_certs_file.write(json.dumps(cert) + '\n')
