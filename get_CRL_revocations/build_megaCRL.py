import multiprocessing
import OpenSSL
import json
import os

from settings import ALL_CRLS_DIR, COMBINED_CRL_OUTFILE

WORKERS = 4


def open_crl(rawtext):
    try:
        return OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, rawtext)
    except:
        pass
    try:
        return OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM, rawtext)
    except:
        return False


def mp_worker(crl_path):
    revoked_data = {}
    revoked_data['path'] = crl_path
    revoked_data['cert_serials'] = []
    revoked_data['crl_issuer'] = []
    try:
        infile = open(crl_path, 'rb')  # read as binary
        rawtext = infile.read()
        infile.close()
    except:
        print("could not open " + crl_path)
        return json.dumps(revoked_data)
    crl = open_crl(rawtext)
    if crl is False:  # if reading failed
        print("could not open " + crl_path)
        return json.dumps(revoked_data)
    revoked_data['crl_issuer'] = crl.get_issuer().get_components()
    revoked = crl.get_revoked()
    if revoked is None:
        return json.dumps(revoked_data, cls=ExtendedJSONEncoder)
    for rvk in revoked:
        serial = rvk.get_serial().decode('utf-8')
        revoked_data['cert_serials'].append(serial)
    return json.dumps(revoked_data, cls=ExtendedJSONEncoder)


class ExtendedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, bytes):
            return o.decode()
        else:
            return super().default(o)


def mp_handler():
    print('searching for crls')
    p = multiprocessing.Pool(WORKERS)
    crl_paths = []
    for path, dirs, files in os.walk(ALL_CRLS_DIR):
        for filename in files:
            crl_paths.append(os.path.join(path, filename))
    print('reading files')
    with open(COMBINED_CRL_OUTFILE, 'w') as f:
        for result in p.imap(mp_worker, crl_paths):
            f.write(result + '\n')


if __name__ == '__main__':
    mp_handler()
