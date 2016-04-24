from ..constructs import Instruction

class Trie(object):
    def __init__(self):
        self.children = [None, None]
        self.value = None

    def __setitem__(self, key, value):
        assert type(value) == Instruction

        node = self
        for bit in [(key >> i) & 0x1 for i in range(64, -1, -1)]:
            if not node.children[bit]:
                node.children[bit] = Trie()
            node = node.children[bit]

        node.value = value

    def __getitem__(self, item):
        if type(item) in (int, long):
            node = self
            for bit in [(item >> i) & 0x1 for i in range(64, -1, -1)]:
                if not node.children[bit]:
                    raise KeyError()
                node = node.children[bit]

            return node.value

        elif type(item) == slice:
            uncommon_bits = (item.stop - item.start).bit_length() + 1

            node = self
            for bit in [(item.start >> i) & 0x1 for i in range(64, uncommon_bits, -1)]:
                if not node.children[bit]:
                    raise KeyError()
                node = node.children[bit]

            return [v for v in iter(node) if item.start <= v.address < item.stop][::item.step]

    def __iter__(self):
        if self.value:
            yield self.value

        for i in range(len(self.children)):
            if self.children[i]:
                for v in self.children[i]:
                    yield v

    def __delitem__(self, key):
        node = self
        for bit in [(key >> i) & 0x1 for i in range(64, -1, -1)]:
            if not node.children[bit]:
                raise KeyError()
            node = node.children[bit]

        if node.value:
            del node.value
