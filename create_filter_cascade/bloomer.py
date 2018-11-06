# A simple-as-possible bloom filter implementation making use of version 3 of the 32-bit murmur
# hash function (for compat with multi-level-bloom-filter-js).
# mgoodwin 2018

import math
import bitarray
import mmh3
from struct import pack

class Bloomer:
    FILE_FMT = b'<dQQ'

    def __init__(self, elements, falsePositiveRate, level):
        self.level = level
        self.elements = elements
        self.falsePositiveRate = falsePositiveRate
        # The ideal size for a bloom filter with a given number of elements and false positive
        # rate is:
        # * - nElements * log(fp rate) / ln(2)^2
        # The ideal number of hash functions is:
        # filter size * ln(2) / number of elements
        # See: https://github.com/bitcoin/bitcoin/blob/master/src/bloom.cpp

        self.nHashFuncs = math.ceil(math.log(1.0 / falsePositiveRate) / math.log(2))
        self.size = math.ceil(1 - (self.nHashFuncs * (elements + 0.5) / math.log(1 - (math.pow(falsePositiveRate, (1 / self.nHashFuncs))))))
        self.bitarray = bitarray.bitarray(self.size, endian = 'little')
        self.bitarray.setall(False)

    def hash(self, seed, key):
        if isinstance(key, str):
            key = key.encode('utf-8')
        else:
            key = str(key).encode('utf-8')
        h = mmh3.hash(key, ((seed * 0xFBA4C795) + (1000000000 * self.level)) & 0xFFFFFFFF)
        return h % self.size

    def add(self, key):
        for i in range(self.nHashFuncs):
            index = self.hash(i, key)
            self.bitarray[index] = True

    def __contains__(self, key):
        for i in range(self.nHashFuncs):
            index = self.hash(i, key)
            if not self.bitarray[index]:
                return False
        return True

    def clear(self):
        self.bitarray.setall(False)

    def tofile(self, f):
        """Write the bloom filter to file object `f'. Underlying bits
        are written as machine values. This is much more space
        efficient than pickling the object."""
        f.write(pack(self.FILE_FMT, self.falsePositiveRate, self.elements,
                     self.level))
        self.bitarray.tofile(f)
        #(f.write(self.bitarray.tobytes()) if is_string_io(f)
        # else self.bitarray.tofile(f))

