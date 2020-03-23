import base64
import unittest
import moz_crlite_lib as crlite

from create_filter_cascade import certs_to_crlite


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


class TestCertListDiff(unittest.TestCase):
    def assertCertListEqual(self, a, b):
        self.assertEqual(len(a), len(b))

        for issuer in a:
            s_a = set(a[issuer])
            s_b = set(b[issuer])
            self.assertEqual(s_a, s_b)

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
