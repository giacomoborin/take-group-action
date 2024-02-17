from linear_equivalence import SF

# SageMath imports
from sage.all import randint, factor, proof, Permutations

from sage.categories.action import Action
from sage.rings.integer import Integer
from sage.rings.integer_ring import ZZ
from sage.rings.rational import Rational
from sage.rings.finite_rings.finite_field_constructor import GF
from sage.matrix.constructor import diagonal_matrix, matrix



def vec(M):
    if type(M) is list:
        buff = [vec(m) for m in M]
        return block_matrix(F,len(M),1,buff)
    else:
        return matrix(F,M.list())

def vec_t(M):
    return matrix(F,M.transpose().list())

class MatrixCode():
    def __init__(self, n, m, k, q, SEED = None, G = None):
        self.n = n
        self.m = m
        self.k = k
        self.q = q
        self.F = GF(q)
        if G:
            self.generator_matrix = G
        else:
            if SEED:
                with seed(SEED): self.generator_matrix = random_matrix(self.F, self.k, self.n * self.m)
            else:
                self.generator_matrix = random_matrix(self.F, self.k, self.n * self.m)
        self.generator_matrix = SF(self.generator_matrix)

    def to_matrix():
        pass

    def to_list():
        pass

    def __repr__(self):
        return f'Matrix [{self.m}*{self.n},{self.k}]_{self.q} code generated by {self.generator_matrix}'




class MatrixCodeIsomorphism():
    def __init__(self, n, m, q, SEED = None, A = None, B = None):
        self.n = n
        self.m = m
        self.q = q
        self.F = GF(q)

        if A and B:
            self.A = A
            self.B = B
        else:
            if SEED:
                with seed(SEED): self.A = random_matrix(self.F, self.m)
                with seed(SEED + ZZ(self.A[0,0])): self.B = random_matrix(self.F, self.n)
            else:
                self.A = random_matrix(self.F, self.n)
                self.B = random_matrix(self.F, self.m)

    def __mul__(self,isom):
        return MatrixCodeIsomorphism(n = self.n, m = self.m, q = self.q, A = self.A * isom.A, B = isom.B * self.B)

    def inverse(self):
        return MatrixCodeIsomorphism(n = self.n, m = self.m, q = self.q, A = self.A.inverse(), B = self.B.inverse())

    def __repr__(self):
        return f'MatrixCodeIsomorphism represented by the matrices\n{self.A}\nand\n{self.B}'

    def __eq__(self,Q):
        return self.perm == Q.perm and self.diag == Q.diag




class MCE(CryptoAction):
    def __init__(self,n,m,k,q,security = 128):
        self.n = n
        self.m = m
        self.k = k
        self.q = q
        self.F = GF(q)
        P = MatrixCodeIsomorphism(n, m, q)
        G = MatrixCode(self.F,n,m,k,q)
        super().__init__(parent(P),parent(G),security)

    def rand_group(self, SEED = None):
        return MatrixCodeIsomorphism(n = self.n, m = self.m, q = self.q, SEED = SEED)

    def rand_set(self, SEED = None):
        return MatrixCode(n = self.n, m = self.m, k = self.k, q = self.q, SEED = SEED)

    def act(self,Q,G):
        if Q in ZZ:
            Q = MonomialMap(n = self.n,q = self.q, SEED = Q)
        Q = Q.to_matrix()
        # [A * C * B for C in code]
        return SF(G*Q)




