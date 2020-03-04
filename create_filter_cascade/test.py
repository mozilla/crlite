import create_filter_cascade.certs_to_crlite as certs_to_crlite
import unittest

from pathlib import Path
import argparse
import base64
import tempfile


class MockFile(object):
    def __init__(self):
        self.data = b""

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        return self.data[idx]

    def write(self, s):
        self.data = self.data + s

    def read(self):
        return self.data

    def flush(self):
        pass


def make_certid(issuer, hex):
    return certs_to_crlite.CertId(base64.urlsafe_b64decode(issuer), bytes.fromhex(hex))


def static_test_certs():
    revoked = {
        b"aG9uZXN0Q0EK": [
            make_certid("aG9uZXN0Q0EK", "00AA"),
            make_certid("aG9uZXN0Q0EK", "AA00"),
        ],
        b"b3RoZXJDQQo=": [
            make_certid("b3RoZXJDQQo=", "FFCCDD")
        ],
    }
    nonrevoked = {
        b"aG9uZXN0Q0EK": [
            make_certid("aG9uZXN0Q0EK", "AAAAAA"),
            make_certid("aG9uZXN0Q0EK", "000000"),
        ],
        b"dGhpcmRDQQo=": [
            make_certid("dGhpcmRDQQo=", "CACACA"),
        ],
    }
    return revoked, nonrevoked


class TestCertLists(unittest.TestCase):
    def assertCertListEqual(self, a, b):
        self.assertEqual(len(a), len(b))

        for issuer in a:
            s_a = set(a[issuer])
            s_b = set(b[issuer])
            self.assertEqual(s_a, s_b)

    def test_save_and_load(self):
        revoked, nonrevoked = static_test_certs()

        with tempfile.TemporaryDirectory() as tmpdirname:
            args = argparse.Namespace()
            args.revokedKeys = tmpdirname / Path("revoked.bin")
            args.validKeys = tmpdirname / Path("valid.bin")

            certs_to_crlite.saveCertLists(args,
                                          revoked_certs_by_issuer=revoked,
                                          nonrevoked_certs_by_issuer=nonrevoked)

            self.assertEqual(Path(args.revokedKeys).stat().st_size, 42)
            self.assertEqual(Path(args.validKeys).stat().st_size, 44)

            loaded_revoked = {}
            loaded_nonrevoked = {}

            certs_to_crlite.loadCertLists(args,
                                          revoked_certs_by_issuer=loaded_revoked,
                                          nonrevoked_certs_by_issuer=loaded_nonrevoked)

            self.assertCertListEqual(loaded_revoked, revoked)
            self.assertCertListEqual(loaded_nonrevoked, nonrevoked)


if __name__ == '__main__':
    unittest.main()
