# Python imports
from hashlib import shake_128
from sage.all import Integer
from math import ceil, log



def cmt(input, lam = 128):
    return to_hex(Integer(int.from_bytes(shake_128(str.encode(str(input))).digest(ceil(lam/8)))),lam = lam)

def to_hex(input, lam = 128):
    if input in ZZ:
        return Integer(input).hex().rjust(2*ceil(lam/8), '0')
    elif set(input) <= {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}:
        return input
    else:
        raise ValueError('Input entry not integer of hexadecimal')

def to_int(input):
    if input in ZZ:
        return input 
    else:
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
    def __init__(self, num_leaves, SALT = None, SEED = None, lam = 128):
        self.num_leaves = num_leaves
        self.lam = lam
        next_power_of_two = 1
        self.deep = 0
        while next_power_of_two < num_leaves:
            next_power_of_two *= 2
            self.deep += 1
        if SEED:
            self.root = to_hex(SEED)
        else:
            self.root = to_hex(randint(0,2**self.lam - 1))
        if SALT:
            self.salt = to_hex(SALT)
        else:
            self.salt = to_hex(randint(0,2**self.lam - 1))
        self.levels = []
        self.construct_tree()
        self.leaves = self.levels[-1][:num_leaves]

    def construct_tree(self):
        # Initialize the bottom level with hashes of individual data elements
        current_level = [self.root]
        self.levels.append(current_level)
        j = 0
        while len(current_level) < self.num_leaves:
            next_level = []
            # Combine adjacent hashes to create parent hashes
            for i in range(0, len(current_level)):
                seed_0, seed_1 = expand_children(SEED = current_level[i], SALT = self.salt, lam = self.lam)
                next_level.append(seed_0)
                next_level.append(seed_1)

            self.levels.append(next_level)
            current_level = next_level
            j += 1 

    def get_root(self):
        return self.levels[0][0]

    def get_leaves(self):
        return self.leaves

    def __repr__(self):
        return f'Seed tree with with {self.num_leaves} leaves and root {self.get_root()}'

    def print_tree(self):
        # just fun Function 
        i = self.deep
        space = '    '
        for level in self.levels:
            print(f'lvl {self.deep - i} :', end=' ')
            for hash in level:
                print(f'{space * (2**i - 1)}{hash[:4]}...{space * (2**i - 1)}', end=' ')
            print('')
            i -= 1
        pass

    def get_cover_single(self, index):
        """
        return a cover to get all the leaves but the index-th one
        """
        pass


    def get_cover(self, subset):
        # Initialize the cover with the given subset of leaves
        cov = cover(subset)
        cover_seeds = []
        level = 0
        for level_cover in cov:
            level += 1
            level_seeds = { (idx,seed) for (idx,seed) in enumerate(self.levels[-level]) if idx in level_cover}
            cover_seeds.append(level_seeds)
        return cover_seeds

def expand_children(SEED, SALT, lam):
        with seed(
                to_int(SALT + SEED)
                ):
            seed_0 = randint(0,2**lam - 1)
            seed_0 = to_hex(seed_0, lam=lam)
            seed_1 = randint(0,2**lam - 1)
            seed_1 = to_hex(seed_1, lam=lam)
        return seed_0, seed_1

def seeds_from_cover(subset,cover_seeds, SALT, dept):
    cov = cover(subset)
    for level in range(len(cov)):
        for index in range(len(cov[level])):
            pass




def one_level_cover(subset):
    buff = []
    subset_copy = subset.copy()
    for x in subset:
        if x % 2 == 0 and (x+1) in subset:
            buff.append(x // 2)
            subset_copy.remove(x)
            subset_copy.remove(x+1)
    return subset_copy,buff


def cover(subset):
    subset_cleared, new_subset = one_level_cover(subset)
    cov = [ subset_cleared ]
    while new_subset:
        subset_cleared, new_subset = one_level_cover(new_subset)
        cov.append(subset_cleared)
    return cov

def N_seed(t,w,max = False):
    if t < w:
        raise ValueError(f'Invalid input for seed cost estimator {t =}, {w =}')
    else:
        return ceil(w * log(t / w, 2))

def l_tail(t, max = False):
    if not max:
        # we use the approximation since it is always a good bound
        return log(t,2)/2
    else:
        return log(t,2)

