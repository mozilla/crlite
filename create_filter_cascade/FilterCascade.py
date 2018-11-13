from bloomer import Bloomer
from struct import pack, unpack, calcsize
import datetime


class FilterCascade:
    FILE_FMT = b'<III'

    def __init__(self, filters, error_rates=[0.02, 0.5]):
        self.filters = filters
        self.error_rates = error_rates

    def initialize(self, set1, set2):
        starttime = datetime.datetime.utcnow()
        print("{} set1 and {} set2".format(len(set1), len(set2)))
        depth = 1
        include = set1
        exclude = set2

        while len(include) > 0:
            er = self.error_rates[-1]
            if depth < len(self.error_rates):
                er = self.error_rates[depth]

            if depth > len(self.filters):
                self.filters.append(
                    Bloomer.filter_with_characteristics(
                        len(exclude), er, depth))

            print("Initializing the {}-depth layer. err={}".format(depth, er))
            filter = self.filters[depth - 1]
            # loop over the elements that *should* be there. Add them to the filter.
            for elem in include:
                filter.add(elem)

            # loop over the elements that should *not* be there. Create a new layer
            # that *includes* the false positives and *excludes* the true positives
            print("Processing false positives")
            false_positives = set()
            for elem in exclude:
                if elem in filter:
                    false_positives.add(elem)

            endtime = datetime.datetime.utcnow()
            print("Took {} ms to process layer {} with bit count {}".format(
                (endtime - starttime).seconds * 1000 +
                (endtime - starttime).microseconds / 1000, depth,
                len(filter.bitarray)))
            if len(exclude) > 0:
                include, exclude = false_positives, include
                depth = depth + 1

    def __contains__(self, elem):
        for layer, filter in [(idx + 1, self.filters[idx])
                              for idx in range(len(self.filters))]:
            even = layer % 2 == 0
            if elem in filter:
                if layer == len(self.filters):
                    return True != even
            else:
                return False != even

    def check(self, entries, exclusions):
        for entry in entries:
            if not entry in self:
                raise Error("oops! false negative!")
        for entry in exclusions:
            if entry in self:
                raise Error("oops! false positive!")

    def bitCount(self):
        total = 0
        for filter in self.filters:
            total = total + len(filter.bitarray)
        return total

    def layerCount(self):
        return len(self.filters)

    def saveDiffMeta(self, f):
        for filter in self.filters:
            f.write(
                pack(FilterCascade.FILE_FMT, filter.size, filter.nHashFuncs,
                     filter.level))

    def tofile(self, f):
        for filter in self.filters:
            filter.tofile(f)

    @classmethod
    def loadDiffMeta(cls, f):
        filters = []
        size = calcsize(FilterCascade.FILE_FMT)
        data = f.read()
        while len(data) >= size:
            filters.append(
                Bloomer(*unpack(FilterCascade.FILE_FMT, data[:size])))
            data = data[size:]
        return FilterCascade(filters)

    @classmethod
    def cascade_with_characteristics(cls, capacity, error_rates, layer=0):
        return FilterCascade(
            [Bloomer.filter_with_characteristics(capacity, error_rates[0])],
            error_rates=error_rates)

    @classmethod
    def fromfile(cls, f):
        buf = f.read()
        layers = Bloomer.from_buf(buf)
        return FilterCascade(layers)
