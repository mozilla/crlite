from struct import pack

from pybloom_live import BloomFilter


class FilterCascade:
    def __init__(self, capacity, oversize_factor, error_rate, depth):
        self.capacity = capacity
        self.error_rate = error_rate
        self.filter = BloomFilter(
            capacity=int(self.capacity * oversize_factor),
            error_rate=self.error_rate
        )
        self.exclusions = []
        self.childLayer = None
        self.depth = depth
        self.oversize_factor = oversize_factor
        self.salt = None

    def initialize(self, entries, exclusions):
        # remove duplicates for this layer
        exclusions = list(set(exclusions))
        entries = list(set(entries))
        # set the "salt" for this layer
        print("Initializing the %s-depth layer." % self.depth)
        entries_length = len(entries)
        exclusions_length = len(exclusions)
        print("%s entries and %s exclusions." % (
            entries_length, exclusions_length
        ))
        self.salt = "a" * self.depth

        # loop over the elements that should be there. Add them to the filter.
        for elem in entries:
            self.filter.add(elem)

        # loop over the elements that should *not* be there. Create a new layer
        # that *includes* the false positives and *excludes* the true positives
        falsePositives = []

        for elem in exclusions:
            if elem in self.filter:
                falsePositives.append(elem)

        if len(falsePositives) > 0:
            self.childLayer = FilterCascade(
                                int(len(falsePositives)),
                                self.oversize_factor,
                                self.error_rate,
                                self.depth + 1
                              )
            # salt entries in some variable but deterministic way
            self.childLayer.initialize(
                [pos + self.salt for pos in falsePositives],
                [pos + self.salt for pos in entries]
            )

    def __contains__(self, elem):
        if elem in self.filter:
            if self.childLayer is None:
                return True
            else:
                return not elem + "a" * self.depth in self.childLayer

    def check(self, entries, exclusions):
        for entry in entries:
            if entry not in self:
                raise ValueError("oops! false negative!")
        for entry in exclusions:
            if entry in self:
                raise ValueError("oops! false positive!")

    def bitCount(self):
        if self.childLayer is None:
            return len(self.filter.bitarray)
        return len(self.filter.bitarray) + self.childLayer.bitCount()

    def layerCount(self):
        if self.childLayer is None:
            return 1
        else:
            return self.childLayer.layerCount() + 1

    def tofile(self, f):
        """
        Write the bloom filter to file object 'f'
        by calling tofile for each layer of the Filter Cascade.
        """
        # print("Writing salt: %s" % self.salt)
        f.write(pack('s', bytes(self.salt, 'utf-8')))
        # print("Writing filter: %s" % self.filter.__dict__)
        f.write(pack('s', bytes(self.filter.hashfn.__name__, 'utf-8')))
        self.filter.tofile(f)
        if self.childLayer is not None:
            self.childLayer.tofile(f)

    def __str__(self):
        returnStr = (
            "FilterCascade Depth: %s:, Capacity: %s, Error Rate: %s, "
            "Hash function: %s, Salt: %s\n" % (
                self.depth, self.capacity, self.error_rate,
                self.filter.hashfn.__name__, self.salt
            )
        )
        if self.childLayer is not None:
            returnStr += str(self.childLayer)
        return returnStr
