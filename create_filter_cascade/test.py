import base64
import tempfile
import unittest

from create_filter_cascade import crlite, certs_to_crlite
from pathlib import Path


class MockFile(object):
    def __init__(self):
        self.data = b""
        self.idx = 0

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        return self.data[idx]

    def write(self, s):
        self.data = self.data + s

    def read(self, count=0xFFFFFFFF):
        data = self.data[self.idx : count + self.idx]
        self.idx += min(count, len(data))
        return data

    def flush(self):
        pass


def make_certid(issuer, hex):
    issuerId = crlite.IssuerId(base64.urlsafe_b64decode(issuer))
    return crlite.CertId(issuerId, bytes.fromhex(hex))


def static_test_certs():
    set1 = {
        b"aG9uZXN0Q0EK": set(
            [make_certid("aG9uZXN0Q0EK", "00AA"), make_certid("aG9uZXN0Q0EK", "AA00")]
        ),
        b"b3RoZXJDQQo=": set([make_certid("b3RoZXJDQQo=", "FFCCDD")]),
    }
    set2 = {
        b"aG9uZXN0Q0EK": set(
            [
                make_certid("aG9uZXN0Q0EK", "AAAAAA"),
                make_certid("aG9uZXN0Q0EK", "000000"),
            ]
        ),
        b"dGhpcmRDQQo=": set([make_certid("dGhpcmRDQQo=", "CACACA")]),
    }
    return set1, set2


class TestStructs(unittest.TestCase):
    def test_write_serial(self):
        f = MockFile()

        with self.assertRaises(Exception):
            crlite.writeSerials(f, [make_certid(b"YQo=", "FF" * 256)])
        self.assertEqual(len(f), 0)

        crlite.writeSerials(f, [make_certid(b"YQo=", "FF" * 255)])
        self.assertEqual(len(f), 256)

    def test_write_issuer(self):
        f = MockFile()

        issuer_base64 = base64.standard_b64encode(b"FF" * 0x20)
        serial_list = set([make_certid(issuer_base64, "CABF00D0")])
        crlite.writeCertListForIssuer(
            file=f, issuer_base64=issuer_base64, serial_list=serial_list
        )
        self.assertEqual(len(f), 74)

        loaded = dict(crlite.readFromCertListByIssuer(f))
        self.assertTrue(issuer_base64 in loaded)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[issuer_base64], serial_list)

    def test_read_write_huge_issuer(self):
        f = MockFile()

        issuer_base64 = base64.standard_b64encode(b"FF" * 254)
        with self.assertRaises(ValueError):
            crlite.writeCertListForIssuer(
                file=f, issuer_base64=issuer_base64, serial_list=[]
            )
        self.assertEqual(len(f), 0)

        issuer_base64 = base64.standard_b64encode(b"FF" * 0x20)
        crlite.writeCertListForIssuer(
            file=f, issuer_base64=issuer_base64, serial_list=[]
        )
        self.assertEqual(len(f), 69)


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
                    crlite.writeCertListForIssuer(
                        file=revfile, issuer_base64=issuer, serial_list=serials
                    )
            with open(nonrevoked_path, "wb") as nonrevfile:
                for issuer, serials in nonrevoked.items():
                    crlite.writeCertListForIssuer(
                        file=nonrevfile, issuer_base64=issuer, serial_list=serials
                    )

            self.assertEqual(revoked_path.stat().st_size, 37)
            self.assertEqual(nonrevoked_path.stat().st_size, 39)

            loaded_revoked = {}
            loaded_nonrevoked = {}

            with open(revoked_path, "rb") as file:
                loaded_revoked = dict(crlite.readFromCertListByIssuer(file))
            with open(nonrevoked_path, "rb") as file:
                loaded_nonrevoked = dict(crlite.readFromCertListByIssuer(file))

            self.assertCertListEqual(loaded_revoked, revoked)
            self.assertCertListEqual(loaded_nonrevoked, nonrevoked)

    def test_save_diff_file(self):
        revoked, _ = static_test_certs()

        with tempfile.TemporaryDirectory() as tmpdirname:
            diff_path = tmpdirname / Path("diff.bin")

            crlite.save_additions(out_path=diff_path, revoked_by_issuer=revoked)

            self.assertEqual(diff_path.stat().st_size, 37)

    def test_make_diff_completely_different(self):
        old, new = static_test_certs()

        diff = certs_to_crlite.find_additions(
            old_by_issuer=iter(old.items()), new_by_issuer=iter(new.items())
        )
        self.assertCertListEqual(new, diff)

    def test_make_diff_one_additional_issuer(self):
        old, _ = static_test_certs()
        addition = {b"bmV3YmllCg==": set([make_certid("bmV3YmllCg==", "012345")])}
        new = old.copy()
        new.update(addition)

        diff = certs_to_crlite.find_additions(
            old_by_issuer=iter(old.items()), new_by_issuer=iter(new.items())
        )
        self.assertCertListEqual(addition, diff)

    def test_make_diff_reverse_order(self):
        set1, _ = static_test_certs()

        diff = certs_to_crlite.find_additions(
            old_by_issuer=iter(set1.items()), new_by_issuer=reversed(list(set1.items()))
        )
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

        diff = certs_to_crlite.find_additions(
            old_by_issuer=iter(combo_set.items()),
            new_by_issuer=reversed(list(new.items())),
        )
        self.assertCertListEqual(addition, diff)

    def test_make_diff_removed_issuer(self):
        old, _ = static_test_certs()
        new = old.copy()
        del new[b"aG9uZXN0Q0EK"]

        diff = certs_to_crlite.find_additions(
            old_by_issuer=iter(old.items()), new_by_issuer=iter(new.items())
        )
        self.assertEqual(len(diff), 0)


if __name__ == "__main__":
    unittest.main()
