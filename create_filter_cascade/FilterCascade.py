# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from bloomer import Bloomer
from struct import pack, unpack, calcsize
import datetime
import logging
log = logging.getLogger(__name__)


class FilterCascade:
    FILE_FMT = b'<III'

    def __init__(self, filters, error_rates=[0.02, 0.5]):
        self.filters = filters
        self.error_rates = error_rates
        self.growth_factor = 1.1
        self.min_filter_length = 10000

    def initialize(self, *, include, exclude):
        log.debug("{} include and {} exclude".format(
            len(include), len(exclude)))
        depth = 1

        while len(include) > 0:
            starttime = datetime.datetime.utcnow()
            er = self.error_rates[-1]
            if depth < len(self.error_rates):
                er = self.error_rates[depth - 1]

            if depth > len(self.filters):
                self.filters.append(
                    # For growth-stability reasons, we force all layers to be at least
                    # min_filter_length large. This is important for the deep layers near the end.
                    Bloomer.filter_with_characteristics(
                        max(
                            int(len(include) * self.growth_factor),
                            self.min_filter_length), er, depth))
            else:
                # Filter already created for this layer. Check size and resize if needed.
                required_size = Bloomer.calc_size(
                    self.filters[depth - 1].nHashFuncs, len(include), er)
                if self.filters[depth - 1].size < required_size:
                    # Resize filter
                    self.filters[depth -
                                 1] = Bloomer.filter_with_characteristics(
                                     int(len(include) * self.growth_factor),
                                     er, depth)
                    log.info("Resized filter at {}-depth layer".format(depth))
            filter = self.filters[depth - 1]
            log.debug(
                "Initializing the {}-depth layer. err={} include={} exclude={} size={} hashes={}"
                .format(depth, er, len(include), len(exclude), filter.size,
                        filter.nHashFuncs))
            # loop over the elements that *should* be there. Add them to the filter.
            for elem in include:
                filter.add(elem)

            # loop over the elements that should *not* be there. Create a new layer
            # that *includes* the false positives and *excludes* the true positives
            log.debug("Processing false positives")
            false_positives = set()
            for elem in exclude:
                if elem in filter:
                    false_positives.add(elem)

            endtime = datetime.datetime.utcnow()
            log.debug(
                "Took {} ms to process layer {} with bit count {}".format(
                    (endtime - starttime).seconds * 1000 +
                    (endtime - starttime).microseconds / 1000, depth,
                    len(filter.bitarray)))
            # Sanity check layer growth.  Bit count should be going down
            # as false positive rate decreases.
            if depth > 2:
                if len(filter.bitarray) > len(
                        self.filters[depth - 3].bitarray):
                    log.error(
                        "Increase in false positive rate detected. depth {} has {} bits and depth {} has {} bits"
                        .format(depth, len(filter.bitarray), depth - 3,
                                len(self.filters[depth - 3].bitarray)))
                    self.filters.clear()
                    return
            include, exclude = false_positives, include
            if len(include) > 0:
                depth = depth + 1
        # Filter characteristics loaded from meta file may result in unused layers.
        # Remove them.
        if depth < len(self.filters):
            del self.filters[depth:]

    def __contains__(self, elem):
        for layer, filter in [(idx + 1, self.filters[idx])
                              for idx in range(len(self.filters))]:
            even = layer % 2 == 0
            if elem in filter:
                if layer == len(self.filters):
                    return True != even
            else:
                return False != even

    def check(self, *, entries, exclusions):
        for entry in entries:
            assert entry in self, "oops! false negative!"
        for entry in exclusions:
            assert not entry in self, "oops! false positive!"

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

    # Follows the bitarray.tofile parameter convention.
    def tofile(self, f):
        for filter in self.filters:
            filter.tofile(f)

    @classmethod
    def loadDiffMeta(cls, f):
        filters = []
        size = calcsize(FilterCascade.FILE_FMT)
        data = f.read()
        while len(data) >= size:
            filtersize, nHashFuncs, level = unpack(FilterCascade.FILE_FMT,
                                                   data[:size])
            filters.append(
                Bloomer(size=filtersize, nHashFuncs=nHashFuncs, level=level))
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
