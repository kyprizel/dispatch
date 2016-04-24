from collections import defaultdict
from itertools import chain, imap
from ..constructs import Instruction

class Trie(object):
    def __init__(self):
        self.children = defaultdict(Trie)
        self.value = None

    def __setitem__(self, key, value):
        assert type(value) == Instruction

        node = self
        for bit in [(key >> i) & 0x1 for i in range(64, -1, -1)]:
            node = node.children[bit]
        node.value = value

    def insert(self, address, value):
        self.__setitem__(address, value)

    def __getitem__(self, item):
        if type(item) == int:
            node = self
            for bit in [(item >> i) & 0x1 for i in range(64, -1, -1)]:
                node = node.children[bit]

            return node.value

        elif type(item) == slice:
            uncommon_bits = (item.stop - item.start).bit_length()

            node = self
            for bit in [(item.start >> i) & 0x1 for i in range(64, uncommon_bits - 1, -1)]:
                node = node.children[bit]

            return [v for v in iter(node) if item.start <= v.address < item.stop][::item.step]

    def get(self, address):
        self.__getitem__(address)

    def __iter__(self):
        for t in chain(*imap(iter, self.children.values())):
            yield t
        if self.value:
            yield self.value

    def __delitem__(self, key):
        node = self
        for bit in [(key >> i) & 0x1 for i in range(64, -1, -1)]:
            node = node.children[bit]

        if node.value:
            del node.value
