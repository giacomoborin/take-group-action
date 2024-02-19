# Python imports
from hashlib import shake_128

# SageMath imports
from sage.all import randint, ZZ, factor, proof
from sage.categories.action import Action



class CryptoAction(Action):
    def __init__(self,G,S,security,is_left=True):
        super().__init__(G,S,is_left = is_left)
        self.security = security

    def rand_set(self, SEED = None):
        with seed(SEED): return (self.domain()).random_element()

    def rand_group(self, SEED = None):
        with seed(SEED): return (self.actor()).random_element()

    def origin(self):
        return self.rand_set(SEED = 1)

    def set_costs(self):
        pass

    def group_costs(self):
        pass

