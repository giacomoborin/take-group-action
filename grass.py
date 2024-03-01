# SageMath imports
from sage.all import randint, ZZ, factor, proof, binomial
from sage.categories.action import Action
from action import CryptoAction
from general_purpose import MerkleTree, SeedTree, cmt, N_seed, l_tail
from math import ceil, log


class GRASS():
    def __init__(self, action: CryptoAction,
                 num_public_keys = 1,
                 fixed_weight = False,
                 w = None,
                 MPC = False,
                 N = 1,
                 skip = False,
                 skip_left = True,
                 num_rounds = None,
                 lam = 128):
        """
        Initializes a GRASS object.

        Parameters:
        - action (CryptoAction): Group action used for the signature.
        - num_public_keys (int): Number of public keys.
        - fixed_weight (bool): Whether to use fixed weight for the signature.
        - w (int): Weight parameter for fixed weight signature.
        - MPC (bool): Whether to use MPC-in-the-Head.
        - N (int): Number of rounds.
        - skip (bool): Whether to skip edges.
        - lam (int): Security parameter.

        Raises:
        - ValueError: If parameters are invalid.
        """
        # group action informations
        self.A = action
        if not action:
            self.origin = None
            # print(f'[GRASS] dummy execution without instantiating the action')
        else:
            self.origin = action.origin()

        # public and private keys
        self.pk = []
        self.sk = []

        # settings for the signature
        self.fixed_weight = fixed_weight
        if self.fixed_weight and not w:
            raise ValueError('Parameter w not setted for fixed weight')
        self.w = w

        self.MPC = MPC
        if not self.MPC and N != 1:
            raise ValueError('With MPC-in-the-Head setting off N must be equal to 1')
        self.N = N
        if not self.MPC and skip:
            raise ValueError('Skipped edges must be used with MPC-in-the-Head')
        self.skip = skip
        if not skip_left and self.fixed_weight:
            raise ValueError('Right Skipped edges incompatible with Fixed Weight')
        self.skip_left = skip_left

        self.lam = lam
        self.num_public_keys = num_public_keys

        # optimal evaluation of the rounds for the security level
        if not self.fixed_weight:
            self.num_rounds = ceil(lam / log(self.num_public_keys*self.N + 1,2))
        else:
            self.num_rounds = self.w + 1
            while ( binomial(self.num_rounds,self.w)*(self.N*self.num_public_keys)**self.w < 2**self.lam ):
                self.num_rounds += 1

        # Variables for commitments
        self.commitment_secrets = None
        self.commit_hash = None
        self.commitment_elements = None

        # Variables for the challenge
        self.ch = None # lam bit string used as seed to generate the challenge

        # Variables for the response
        self.resp = []

        # Group action evaluation for the algorithm
        self.group_actions_signing = self.num_rounds*self.N
        # plain MPC case
        if not self.skip:
            self.group_actions_verify = self.group_actions_signing
        # skip case, no FW
        elif not self.fixed_weight:
            self.group_actions_verify = self.num_rounds*ceil(1 + self.N/2)
        # skip case, with FW
        else:
            self.group_actions_verify = self.num_rounds + self.w*ceil((1+self.N)/2)





    def size(self, set_cost, group_cost, bytes = False, max = False):
        """
        Computes the size of various components.

        Parameters:
        - set_cost (int): Cost of set operations.
        - group_cost (int): Cost of group operations.
        - bytes (bool): Whether to return size in bytes.
        - max (bool): Whether to return max or average size of the signature.

        Returns:
        - dict: Size of public key, signature, group actions, and verification group actions.
        """
        lam = self.lam
        if bytes:
            lam /= 8

        # the case for MPCitH is handled by the fact that for N = 1 
        # the formulas for the signature are equivalent (log(N,2)=0)
        # since the advantage is clear we always use seed tree

        if self.fixed_weight:
            # rows 10 and 14
            sig = self.w * (group_cost + ceil(log(self.N,2)) * lam) + N_seed(t = self.num_rounds, w = self.w, max = max)*lam + 3 * lam
            # rows 19 and 20
            if self.skip and self.skip_left:
                sig += 2 * lam * N_seed(t = self.num_rounds, w = self.w, max = max)
                sig += w * 2 * lam * l_tail(t = self.N - 1, max = max)
        # no use of fixed weight
        else:
            # rows 2 and 12
            if max:
                sig = self.num_rounds * (group_cost + ceil(log(self.N,2))*lam) + 3 * lam
            else:
                sig = self.num_rounds * ceil(
                    (1 - 1/(self.num_public_keys*self.N + 1)) * (group_cost + ceil(log(self.N,2))*lam) + 
                    (1/(self.num_public_keys*self.N + 1)) * lam ) + 3*lam
            # rows 17 and 18, we are using (41) and (42)
            if self.skip and self.skip_left:
                sig += self.num_rounds * 2 * lam * l_tail(t = self.N - 1, max = max)
            elif self.skip and not self.skip_left:
                raise ValueError("Right Skip signature sizes not implemented")

        costs = {
            'pub_key' : ceil(set_cost*self.num_public_keys + lam),
            'signature' : ceil(sig),
            'group_actions' : self.group_actions_verify,
            'ver_group_actions' : self.group_actions_signing
        }
        return costs

    def keygen(self):
        """
        Returns the public key.

        Returns:
        - list: Public key.
        """
        self.pk = []
        self.sk = []
        for i in range(self.num_public_keys):
            key = self.A.rand_group()
            self.sk.append(key)
            self.pk.append(self.A.act(key,self.origin))
        return self.pk

    def export_public_key(self):
        """
        Returns the public key.

        Returns:
        - list: Public key.
        """
        if self.pk is None:
            raise ValueError(f"Must first generate a keypair with `self.keygen()`")
        return self.pk

    def commitment(self):
        """
        Generates commitment.

        Returns:
        - int: Commitment hash.
        """

        self.commitment_secrets = [randint(0,2**self.lam - 1) for _ in range(self.num_rounds)]
        if not self.num_public_keysPC:
            self.commitment_elements = [self.A.act(SEED,self.origin) for SEED in self.commitment_secrets]
            self.commit_hash = cmt([cmt(x) for x in self.commitment_elements],lam = self.lam)
        else:
            raise ValueError('MPC-in-the-Head not implemented')
            # generation of element via SeedTree()
            # sequential appliation to the origin
            self.commit_hash = cmt([MerkleTree(data) for data in self.commitment_elements],lam = self.lam)
        return self.commit_hash


    def challenge(self):
        """
        Generates a list of random challenges for each
        round of the protocol.

        Returns:
        - list: Challenge.
        """
        if self.fixed_weight:
            if self.num_public_keysPC:
                raise ValueError('Challenge for MPC not yet implemented')
            else:
                buff = [0] * (self.num_rounds - self.w) + [randint(1,self.num_public_keys) for _ in range(self.w)]
            shuffle(buff)
            return buff
        elif self.num_public_keysPC:
            raise ValueError('Challenge for MPC not yet implemented')
        else:
            return [randint(0,self.num_public_keys) for _ in range(self.num_rounds)]

    def challenge_from_message(self, msg, ch = None):
        """
        Compute a challenge deterministically from a
        message

        Returns:
        - list: Challenge.
        """
        if ch:
            self.ch = ch
        else:
            self.ch = cmt([self.commit_hash,msg])
        with seed(ZZ('0x' + self.ch)): CH = self.challenge()
        return CH

    def response(self,ch):
        """
        Generates a response for the challenge.

        Parameters:
        - ch: Challenge.

        Returns:
        - list: Response.
        """
        if self.pk is None or self.sk is None:
            raise ValueError(f"Must first generate a keypair with `self.keygen()`")

        if self.commitment_secrets is None:
            raise ValueError(
                f"Must first generate a commitment with `self.commitment()`"
            )

        for idx, x in enumerate(self.commitment_secrets):
            if ch[idx] == 0:
                self.resp.append(x)
            else:
                gtilde = self.A.rand_group(SEED = x)
                self.resp.append(self.sk[ch[idx] - 1].inverse() * gtilde)
        return self.resp

    def sign(self, msg):
        """
        Signs a message.

        Parameters:
        - msg: Message to be signed.

        Returns:
        - tuple: Signature tuple (CH, RESP), where CH is the commitment hash and RESP is the response.
        """
        # Make a commitment 
        COM = self.commitment()

        # Use the message to find a challenge
        CH = self.challenge_from_message(msg)

        # Compute a response for the challenge
        RESP = self.response(CH)

        return Integer(self.ch), RESP

    def commit_recover(self, CH, RESP):
        """
        Recovers commitment.

        Parameters:
        - CH: Commitment hash.
        - RESP: Response.

        Returns:
        - int: New commitment hash.
        """
        new_commitment_elements = []
        with seed(ZZ('0x' + CH)): challenges = self.challenge()
        for idx, c in enumerate(challenges):
            if c == 0:
                new_commitment_elements.append(cmt(self.A.act(RESP[idx],self.origin)))
            else:
                new_commitment_elements.append(cmt(self.A.act(RESP[idx],self.pk[c - 1])))
        COM = cmt(new_commitment_elements)
        return COM

    def verify(self, sig , msg):
        """
        Verifies the signature.

        Parameters:
        - sig: Signature.
        - msg: Message.

        Returns:
        - bool: True if signature is valid, False otherwise.
        """
        CH, RESP = sig
        COM = self.commit_recover(CH, RESP)
        return cmt([COM,msg]) == CH
