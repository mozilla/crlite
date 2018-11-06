from bloomer import Bloomer
from struct import pack, unpack, calcsize
import datetime
import json

class FilterCascade:
    FILE_FMT = b'<QddQ'
    def __init__(self, capacity, oversize_factor, error_rate, depth):
        self.capacity  = capacity
        self.error_rate = error_rate
        self.filter = Bloomer(elements = int(self.capacity * oversize_factor), falsePositiveRate = self.error_rate, level = depth)
        self.exclusions = []
        self.childLayer = None
        self.depth = depth
        self.oversize_factor = oversize_factor

    def initialize(self, entries, exclusions):
        starttime = datetime.datetime.utcnow()
        print("Initializing the %s-depth layer. err=%f" % (self.depth, self.error_rate))
        print("%s entries and %s exclusions." % (len(entries), len(exclusions)))

        # loop over the elements that *should* be there. Add them to the filter.
        for elem in entries:
            self.filter.add(elem)

        # loop over the elements that should *not* be there. Create a new layer
        # that *includes* the false positives and *excludes* the true positives
        falsePositives = []

        print("Processing false positivies")
        for elem in exclusions:
            if elem in self.filter:
                falsePositives.append(elem)
        exclusions.clear()

        er = self.error_rate
        #if self.depth >= 1:
        #    er = 0.5
        endtime = datetime.datetime.utcnow()
        print("Took %d ms to process layer %s with bit count %d" % ((endtime - starttime).seconds * 1000 + (endtime - starttime).microseconds/1000, self.depth, len(self.filter.bitarray)))
        if len(falsePositives) > 0:
            if self.childLayer == None:
                self.childLayer = FilterCascade(int(len(falsePositives)), self.oversize_factor, er, self.depth + 1)
            self.childLayer.initialize( falsePositives, entries)
        else:
            self.childLayer = None

    def __contains__(self, elem):
        if elem in self.filter:
            if None == self.childLayer:
                return True
            else:
                return not elem in self.childLayer

    def check(self, entries, exclusions):
        for entry in entries:
            if not entry in self:
                raise Error("oops! false negative!")
        for entry in exclusions:
            if entry in self:
                raise Error("oops! false positive!")

    def bitCount(self):
        if None == self.childLayer:
            return len(self.filter.bitarray)
        return len(self.filter.bitarray) + self.childLayer.bitCount()

    def layerCount(self):
        if None == self.childLayer:
            return 1
        else:
            return self.childLayer.layerCount() + 1

    @classmethod
    def loadDiffMeta(cls, f):
        data = f.readline()
        if data:
            meta = json.loads(data)
            layer = FilterCascade(meta['capacity'], meta['oversize_factor'], meta['error_rate'], meta['depth'])
            layer.childLayer = FilterCascade.loadDiffMeta(f)
            return layer
        else:
            return None

    def saveDiffMeta(self, f):
        meta = dict()
        meta['capacity'] = self.capacity
        meta['oversize_factor'] = self.oversize_factor
        meta['error_rate'] = self.error_rate
        meta['depth'] = self.depth
        f.write(json.dumps(meta))
        f.write("\n")
        if self.childLayer is None:
            print("we're at the bottom of the cascade!\n"
                  "No need to write any more")
        else:
            self.childLayer.saveDiffMeta(f)

    def tofile(self, f):
        """
        Write the bloom filter to file object 'f'
        by calling tofile for each layer of the Filter Cascade.
        """
        self.filter.tofile(f)
        if self.childLayer is None:
            print("we're at the bottom of the cascade!\n"
                  "No need to write any more")
        else:
            self.childLayer.tofile(f)

