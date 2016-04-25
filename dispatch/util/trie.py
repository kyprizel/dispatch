from ..constructs import Instruction

class Trie(object):
    BUCKET_LEN = 1
    BUCKET_MASK = 0b1
    def __init__(self):
        self.children = [None for _ in range(2**Trie.BUCKET_LEN)]
        self.value = None

    def __setitem__(self, key, value):
        assert type(value) == Instruction

        node = self
        for bucket in \
                [(key >> i) & Trie.BUCKET_MASK for \
                 i in range(64, -1, -Trie.BUCKET_LEN)]:
            if not node.children[bucket]:
                node.children[bucket] = Trie()
            node = node.children[bucket]

        node.value = value

    def __getitem__(self, item):
        if type(item) in (int, long):
            node = self
            for bucket in \
                    [(item >> i) & Trie.BUCKET_MASK for \
                     i in range(64, -1, -Trie.BUCKET_LEN)]:
                if not node.children[bucket]:
                    raise KeyError()
                node = node.children[bucket]

            return node.value

        elif type(item) == slice:
            uncommon_bits = (item.stop - item.start).bit_length() + 1

            node = self
            for bucket in \
                    [(item.start >> i) & Trie.BUCKET_MASK \
                     for i in range(64, uncommon_bits, -Trie.BUCKET_LEN)]:
                if not node.children[bucket]:
                    raise KeyError()
                node = node.children[bucket]

            return [v for v in iter(node) if item.start <= v.address < item.stop][::item.step]

    def __iter__(self):
        if self.value:
            yield self.value

        for i in range(len(self.children)):
            if self.children[i]:
                for v in self.children[i]:
                    yield v

    def __contains__(self, item):
        node = self
        for bucket in \
                [(item >> i) & Trie.BUCKET_MASK for \
                i in range(64, -1, -Trie.BUCKET_LEN)]:
            if not node.children[bucket]:
                return False
            node = node.children[bucket]
        return True

    def __delitem__(self, key):
        node = self
        for bucket in \
                [(key >> i) & Trie.BUCKET_MASK \
                 for i in range(64, -1, -Trie.BUCKET_LEN)]:
            if not node.children[bucket]:
                raise KeyError()
            node = node.children[bucket]

        if node.value:
            del node.value
