import create_filter_cascade.certs_to_crlite as certs_to_crlite
import unittest

from pathlib import Path
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
    issuerId = certs_to_crlite.IssuerId(base64.urlsafe_b64decode(issuer))
    return certs_to_crlite.CertId(issuerId, bytes.fromhex(hex))


def static_test_certs():
    set1 = {
        b"aG9uZXN0Q0EK": set([
            make_certid("aG9uZXN0Q0EK", "00AA"),
            make_certid("aG9uZXN0Q0EK", "AA00"),
        ]),
        b"b3RoZXJDQQo=": set([
            make_certid("b3RoZXJDQQo=", "FFCCDD")
        ]),
    }
    set2 = {
        b"aG9uZXN0Q0EK": set([
            make_certid("aG9uZXN0Q0EK", "AAAAAA"),
            make_certid("aG9uZXN0Q0EK", "000000"),
        ]),
        b"dGhpcmRDQQo=": set([
            make_certid("dGhpcmRDQQo=", "CACACA"),
        ]),
    }
    return set1, set2


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
            revoked_path = tmpdirname / Path("revoked.bin")
            nonrevoked_path = tmpdirname / Path("valid.bin")

            with open(revoked_path, "wb") as revfile:
                for issuer, serials in revoked.items():
                    certs_to_crlite.writeCertListForIssuer(file=revfile,
                                                           issuer_base64=issuer,
                                                           serial_list=serials)
            with open(nonrevoked_path, "wb") as nonrevfile:
                for issuer, serials in nonrevoked.items():
                    certs_to_crlite.writeCertListForIssuer(file=nonrevfile,
                                                           issuer_base64=issuer,
                                                           serial_list=serials)

            self.assertEqual(revoked_path.stat().st_size, 42)
            self.assertEqual(nonrevoked_path.stat().st_size, 44)

            loaded_revoked = {}
            loaded_nonrevoked = {}

            certs_to_crlite.loadCertLists(revoked_path=revoked_path,
                                          nonrevoked_path=nonrevoked_path,
                                          revoked_certs_by_issuer=loaded_revoked,
                                          nonrevoked_certs_by_issuer=loaded_nonrevoked)

            self.assertCertListEqual(loaded_revoked, revoked)
            self.assertCertListEqual(loaded_nonrevoked, nonrevoked)

    def test_save_diff_file(self):
        revoked, nonrevoked = static_test_certs()

        with tempfile.TemporaryDirectory() as tmpdirname:
            diff_path = tmpdirname / Path("diff.bin")

            certs_to_crlite.save_additions(out_path=diff_path,
                                           revoked_by_issuer=revoked,
                                           nonrevoked_by_issuer=nonrevoked)

            self.assertEqual(diff_path.stat().st_size, 83)

    def test_make_diff_completely_different(self):
        old, new = static_test_certs()

        diff = certs_to_crlite.find_additions(old_by_issuer=iter(old.items()),
                                              new_by_issuer=iter(new.items()))
        self.assertCertListEqual(new, diff)

    def test_make_diff_one_additional_issuer(self):
        old, _ = static_test_certs()
        addition = {
            b"bmV3YmllCg==": set([make_certid("bmV3YmllCg==", "012345")])
        }
        new = old.copy()
        new.update(addition)

        diff = certs_to_crlite.find_additions(old_by_issuer=iter(old.items()),
                                              new_by_issuer=iter(new.items()))
        self.assertCertListEqual(addition, diff)

    def test_make_diff_reverse_order(self):
        set1, _ = static_test_certs()

        diff = certs_to_crlite.find_additions(old_by_issuer=iter(set1.items()),
                                              new_by_issuer=reversed(list(set1.items())))
        self.assertEqual(len(diff), 0)

    def test_make_diff_reverse_order_add_one(self):
        set1, set2 = static_test_certs()
        combo_set = set1.copy()
        combo_set.update(set2)
        addition = {
            b"bmV3YmllCg==": set([make_certid("bmV3YmllCg==", "012345")]),
        }
        new = combo_set.copy()
        new.update(addition)

        diff = certs_to_crlite.find_additions(old_by_issuer=iter(combo_set.items()),
                                              new_by_issuer=reversed(list(new.items())))
        self.assertCertListEqual(addition, diff)

    def test_make_diff_removed_issuer(self):
        old, _ = static_test_certs()
        new = old.copy()
        del new[b"aG9uZXN0Q0EK"]

        diff = certs_to_crlite.find_additions(old_by_issuer=iter(old.items()),
                                              new_by_issuer=iter(new.items()))
        self.assertEqual(len(diff), 0)


if __name__ == '__main__':
    unittest.main()
