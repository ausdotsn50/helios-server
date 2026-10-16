"""
Paillier datatypes for Helios.
"""

from helios.crypto import paillier as crypto_paillier
from helios.datatypes import LDObject, arrayOf


class PaillierObject(LDObject):
    WRAPPED_OBJ_CLASS = dict
    USE_JSON_LD = False


class PublicKey(PaillierObject):
    """
    A Paillier public key: {n, g}, plus {h, hn, djn41_mode} under DJN 4.1.

    The 4.1 fields are emitted ONLY when the key is in a DJN mode, rather than
    being declared in FIELDS and serialized as nulls on a standard key. Two
    reasons:

    1. A standard key's serialization is then byte-for-byte what it was before
       4.1 existed, so stored elections and the B8 ballot-size canary are
       unaffected.
    2. The mode travels with the key. The booth sees only the public key, and
       a 'short' key and a 'long' key differ in nothing else, so a key that
       round-trips through the database comes back in the mode it went in.

    Both shapes reach this class from the 'legacy/EGPublicKey' hint too: the
    shape dispatch in helios/datatypes/__init__.py keys on 'y' being absent and
    'n' present, which holds for either.
    """
    WRAPPED_OBJ_CLASS = crypto_paillier.PaillierPublicKey
    FIELDS = ['n', 'g']
    STRUCTURED_FIELDS = {
        'n': 'core/BigInteger',
        'g': 'core/BigInteger'}

    # Serialized alongside FIELDS on a DJN key. Not in FIELDS itself, because
    # LDObject.loadDataFromDict indexes d[f] unconditionally and would raise
    # KeyError on every standard key.
    DJN41_FIELDS = ['h', 'hn', 'djn41_mode']

    def toDict(self, complete=False):
        d = super(PublicKey, self).toDict(complete=complete)

        pk = self.wrapped_obj
        if pk.uses_djn_41:
            for f in self.DJN41_FIELDS:
                d[f] = str(getattr(pk, f))

        return d

    def loadDataFromDict(self, d):
        super(PublicKey, self).loadDataFromDict(d)

        # Parsed by the same function as PaillierPublicKey.from_dict, which
        # also refuses the retired (h, g_prime) format.
        for f, value in crypto_paillier.djn41_fields_from_dict(d).items():
            setattr(self.wrapped_obj, f, value)


class SecretKey(PaillierObject):
    WRAPPED_OBJ_CLASS = crypto_paillier.PaillierSecretKey
    FIELDS = ['public_key', 'p', 'q', 'lambda_', 'mu']
    STRUCTURED_FIELDS = {
        'public_key': 'paillier/PublicKey',
        'p': 'core/BigInteger',
        'q': 'core/BigInteger',
        'lambda_': 'core/BigInteger',
        'mu': 'core/BigInteger'}


class Ciphertext(PaillierObject):
    WRAPPED_OBJ_CLASS = crypto_paillier.PaillierCiphertext
    FIELDS = ['c']
    STRUCTURED_FIELDS = {
        'c': 'core/BigInteger'}


class ZKProof(PaillierObject):
    """
    One Pi_root transcript.

    `commitment` is a plain big integer, where legacy/EGZKProof's is a nested
    legacy/EGZKProofCommitment of {A, B}. Chaum-Pedersen commits to two values;
    Pi_root commits to one. That difference is also the discriminator
    helios/datatypes/__init__.py dispatches on.
    """
    WRAPPED_OBJ_CLASS = crypto_paillier.PaillierZKProof
    FIELDS = ['commitment', 'challenge', 'response']
    STRUCTURED_FIELDS = {
        'commitment': 'core/BigInteger',
        'challenge': 'core/BigInteger',
        'response': 'core/BigInteger'}


class ZKDisjunctiveProof(PaillierObject):
    WRAPPED_OBJ_CLASS = crypto_paillier.PaillierZKDisjunctiveProof
    FIELDS = ['proofs']
    STRUCTURED_FIELDS = {
        'proofs': arrayOf('paillier/ZKProof')}

    def loadDataFromDict(self, d):
        "hijack and make sure we add the proofs name back on"
        return super(ZKDisjunctiveProof, self).loadDataFromDict({'proofs': d})

    def toDict(self, complete=False):
        "hijack toDict and return the proofs array only, matching legacy"
        return super(ZKDisjunctiveProof, self).toDict(complete=complete)['proofs']
