# SageMath imports
from sage.all import randint, factor, proof, Permutations

from sage.categories.action import Action
from sage.rings.integer import Integer
from sage.rings.integer_ring import ZZ
from sage.rings.rational import Rational
from sage.rings.finite_rings.finite_field_constructor import GF
from sage.matrix.constructor import diagonal_matrix, matrix
#from sage.matrix.matrix2 import rref
from sage.coding.linear_code import LinearCode

from general_purpose import cmt



# general purpose stuff
def SF(G):
    k,n = G.dimensions()
    if k > n:
        print(f'[SF DEBUG] matrix G is {k}x{n}, not horizontal, transposing it')
        return SF(G.transpose())
    sol = G.rref()
    if sol[:,:k].is_singular():
        raise ValueError('input matrix without systematic form')
    return sol

class CryptoLinearCode(LinearCode):
    """
    Child class to sage.coding.linear_code.LinearCode with specific 
    functions for Cryptographic use meant for using code equivalence.

    The class should be adapted to handle also Canonical Forms
    """
    def __init__(self, n, k, q, G = None, SEED = None, lam = 128):
        self.n = n
        self.k = k
        self.q = q
        self.F = GF(q)
        self.lam = lam
        if G:
            if G[:,:k].is_singular():
                raise ValueError('input matrix without systematic form')
            super().__init__(G)
        else:
            with seed(SEED): G = random_matrix(self.F,k,n)
            while G[:,:k].is_singular():
                with seed(SEED): SEED = randint(0,2**self.lam - 1)
                with seed(SEED): G = random_matrix(self.F,k,n)
            super().__init__(G)
        # here we rewrite the internal matrix so that only the sf one is stored
        self._generator_matrix = self.systematic_generator_matrix()

    def __repr__(self):
        sup_repr = super().__repr__()
        return f'{sup_repr} with hashed generator matrix = {cmt(self._generator_matrix,lam = self.lam)}'

    @cached_method
    def get_action(self):
        action = LCE(n = self.n, k = self.k, q = self.q)
        return action

    def act(self, Q):
        action = self.get_action()
        return action.act(Q, self)






class MonomialMap(Parent):
    def __init__(self,n,q,P = None, D = None, SEED = None):
        self.n = n
        self.q = q
        self.F = GF(q)
        self.V = self.F**n
        if not P:
            with seed(SEED): P = Permutations(n).random_element()
        if not D:
            with seed(SEED): D = self.V([randint(1,q-1) for _ in range(n)])
        self.perm = P
        self.diag = D

    def to_matrix(self):
        return (self.perm.to_matrix())*diagonal_matrix(self.diag)

    def __repr__(self):
        return f'Monomial map permuting with {self.perm} and rescaling by {self.diag}'

    def __mul__(self,Q):
        return MonomialMap(n = self.n, q = self.q, P =  Q.perm * self.perm, D = self.V((Q.perm).action(self.diag)).pairwise_product(Q.diag))

    def inverse(self):
        D = self.V((self.perm.inverse()).action(self.diag))
        return MonomialMap(n = self.n, q = self.q, P =  self.perm.inverse(), D = self.V([ a**-1 for a in D]))

    def __truediv__(self, Q):
        return self * Q.inverse()

    def __eq__(self,Q):
        return self.perm == Q.perm and self.diag == Q.diag

    def is_one(self):
        return self.perm.is_one() and set(self.diag) == {1}


class LCE(CryptoAction):
    def __init__(self,n,k,q,security = 128):
        self.n = n
        self.k = k
        self.q = q
        self.F = GF(q)
        P = MonomialMap(n,q)
        C = CryptoLinearCode(n, k, q, SEED = 1)
        super().__init__(parent(P),category(C),security, is_left = False)

    def rand_group(self, SEED = None):
        return MonomialMap(self.n,self.q,SEED = SEED)

    def rand_set(self, SEED = None):
        return CryptoLinearCode(n = self.n, k = self.k, q = self.q, SEED = SEED)

    def act(self,Q,C):
        if Q in ZZ:
            Q = MonomialMap(n = self.n,q = self.q, SEED = Q)
        G_out = C.generator_matrix()*Q.to_matrix()
        OUT = CryptoLinearCode(n = C.n, k = C.k, q = C.q, G = G_out)
        return OUT

    def _act_(self,Q,C):
        """
        Does not work when Q is a seed!
        """
        if Q in ZZ:
            Q = MonomialMap(n = self.n,q = self.q, SEED = Q)
        return self.act(Q,C)


