# Python imports
from hashlib import shake_128
from sage.functions.other import Function_ceil


def cmt(input, lam = 128):
    return to_hex(Integer(int.from_bytes(shake_128(str.encode(str(input))).digest(ceil(lam/8)))),lam = lam)

def to_hex(input, lam = 128):
    return Integer(input).hex().rjust(2*ceil(lam/8), '0')

def to_int(input):
    return ZZ('0x' + input)

# memo for HEX -> int do s -> ZZ('0x'+s)

class MerkleTree:
    def __init__(self, data):
        self.intial_len = len(data)
        length = len(data)
        next_power_of_two = 1
        self.deep = 0
        while next_power_of_two < length:
            next_power_of_two *= 2
            self.deep += 1
        if next_power_of_two > length:
            padding = next_power_of_two - length
            data.extend(['0'] * padding)
        self.data = data
        self.levels = []
        self.construct_tree(data)

    def construct_tree(self, data):
        # Initialize the bottom level with hashes of individual data elements
        current_level = [cmt(d) for d in data]
        self.levels.append(current_level)

        while len(current_level) > 1:
            next_level = []
            # Combine adjacent hashes to create parent hashes
            for i in range(0, len(current_level), 2):
                hash_pair = current_level[i] + current_level[i+1] if i+1 < len(current_level) else current_level[i]
                next_level.append(cmt(hash_pair))
            self.levels.append(next_level)
            current_level = next_level

    def get_root(self):
        return self.levels[-1][0]

    def __repr__(self):
        return f'Merkle tree with {self.deep} levels, for {self.intial_len} entries and root {self.get_root()}'

    def print_tree(self):
        i = 0
        space = '    '
        for level in self.levels:
            print(f'lvl {self.deep - i} :', end=' ')
            for hash in level:
                print(f'{space * (2**i - 1)}{hash[:4]}...{space * (2**i - 1)}', end=' ')
            print('')
            i += 1
            
    def tail_cover(self, x, left = True):
        # Returns the cover of the left tail of the tree using x consecutive entries
        if x == len(self.data):
            return self.get_root()
        elif x > len(self.data):
            raise ValueError(f'Tail lenght {x} higher then data lenght {self.data}')
        bin = x.binary().rjust(self.deep,'0')
        print(bin)
        cover = []
        j = 1
        for (idx,c) in enumerate(bin):
            internal_idx = ZZ('0b'+bin[:j])
            level_hashes = self.levels[self.deep - idx - 1]
            # print(f'{idx = }, {internal_idx = }, {c = }')
            # print([h[:8] + '...' for h in level_hashes])
            if c == '1':
                if not left:
                    level_hashes.reverse()
                cover.append(level_hashes[internal_idx - 1])
            j += 1

        return cover

def tail_cover_verify(cover, data, root, initial_len = None, left = True, ground_level = True):
    if ground_level:
        if left:
            if initial_len:
                length = len(data)
                next_power_of_two = 1
                while next_power_of_two < initial_len:
                    next_power_of_two *= 2
                if next_power_of_two > length:
                    padding = next_power_of_two - initial_len
                    data.extend(['0'] * padding)
            data.reverse()
        data = [cmt(d) for d in data]
    elif not cover and len(data) == 1:
        return root == data[0]
        
    if len(data) % 2:
        data.append(cover.pop())
    # print([h[:4] + '...' for h in data])

    if left:
        new_data = [cmt(data[2*i+1] + data[2*i]) for i in range(len(data)//2)]
    else:
        new_data = [cmt(data[2*i] + data[2*i+1]) for i in range(len(data)//2)]
    
    return tail_cover_verify(cover, new_data, root, left = left, ground_level = False)
            
    
class SeedTree():
    pass


