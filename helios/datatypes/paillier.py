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
    A Paillier public key: {n, g}, plus {h, hn, djn41_mode} under DJN 4.1
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
