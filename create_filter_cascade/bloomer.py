# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# A simple-as-possible bloom filter implementation making use of version 3 of the 32-bit murmur
# hash function (for compat with multi-level-bloom-filter-js).
# mgoodwin 2018

import math
import bitarray
import mmh3
from struct import pack, unpack
import logging
log = logging.getLogger(__name__)


class Bloomer:
    FILE_FMT = b'<III'

    def __init__(self, *, size, nHashFuncs, level):
        self.nHashFuncs = nHashFuncs
        self.size = size
        self.level = level

        self.bitarray = bitarray.bitarray(self.size, endian='little')
        self.bitarray.setall(False)

    def hash(self, seed, key):
        if not isinstance(key, bytes):
            if isinstance(key, str):
                key = key.encode('utf-8')
            else:
                key = str(key).encode('utf-8')
        # log.debug("key is {}".format([c for c in key]))
        hash_seed = ((seed << 16) + self.level) & 0xFFFFFFFF
        h = (mmh3.hash(key, hash_seed) & 0xFFFFFFFF) % self.size
        # log.debug("h is {}".format(h))
        return h

    def add(self, key):
        for i in range(self.nHashFuncs):
            index = self.hash(i, key)
            self.bitarray[index] = True

    def __contains__(self, key):
        for i in range(self.nHashFuncs):
            index = self.hash(i, key)
            if not self.bitarray[index]:
                # log.debug("not in {}#{}".format(self.level, i))
                return False
            #else:
            #    log.debug("in {}#{}".format(self.level, i))
        return True

    def clear(self):
        self.bitarray.setall(False)

    # Follows the bitarray.tofile parameter convention.
    def tofile(self, f):
        """Write the bloom filter to file object `f'. Underlying bits
        are written as machine values. This is much more space
        efficient than pickling the object."""
        f.write(pack(self.FILE_FMT, self.size, self.nHashFuncs, self.level))
        f.flush()
        self.bitarray.tofile(f)

    @classmethod
    def filter_with_characteristics(cls, elements, falsePositiveRate, level=1):
        nHashFuncs = Bloomer.calc_n_hashes(falsePositiveRate)
        size = Bloomer.calc_size(nHashFuncs, elements, falsePositiveRate)
        return Bloomer(size=size, nHashFuncs=nHashFuncs, level=level)

    @classmethod
    def calc_n_hashes(cls, falsePositiveRate):
        return math.ceil(math.log(1.0 / falsePositiveRate) / math.log(2))

    @classmethod
    def calc_size(cls, nHashFuncs, elements, falsePositiveRate):
        return math.ceil(1 - (nHashFuncs * (elements + 0.5) / math.log(
            1 - (math.pow(falsePositiveRate, (1 / nHashFuncs))))))

    @classmethod
    def from_buf(cls, buf):
        filters = []
        while len(buf) > 0:
            log.debug(len(buf))
            size, nHashFuncs, level = unpack(Bloomer.FILE_FMT, buf[0:12])
            byte_count = math.ceil(size / 8)
            ba = bitarray.bitarray(endian="little")
            ba.frombytes(buf[12:12 + byte_count])
            buf = buf[12 + byte_count:]
            bloomer = Bloomer(size=1, nHashFuncs=nHashFuncs, level=level)
            bloomer.size = size
            log.debug("Size is {}, level {}, nHashFuncs, {}".format(
                size, level, nHashFuncs))
            bloomer.bitarray = ba
            filters.append(bloomer)
        return filters
