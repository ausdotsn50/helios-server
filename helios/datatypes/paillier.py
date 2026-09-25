"""
Paillier datatypes for Helios.

Mirrors legacy.py's structure for the Paillier arm. These are the LDObject
wrappers that helios/datatypes/__init__.py routes to when a serialized object's
shape identifies it as Paillier rather than ElGamal, or when the wrapped object
declares its own `paillier/...` datatype.

TWO THINGS HERE ARE NOT OPTIONAL:

1. Every field appears in STRUCTURED_FIELDS. LDObject.toDict does

       if not self.structured_fields:
           if self.wrapped_obj.alias is not None:    # Voter-specific

   so a datatype with no structured fields raises
   `AttributeError: 'PaillierCiphertext' object has no attribute 'alias'` from
   deep inside serialization. Every Paillier field is a big integer, so
   declaring them all is natural rather than a workaround.

2. ZKDisjunctiveProof serializes as a BARE ARRAY. This copies
   legacy.EGZKDisjunctiveProof, which overrides toDict to return ...['proofs']
   rather than the wrapping object. Get it wrong and `individual_proofs` changes
   shape, which silently breaks the harness's proof_bytes slice -- silently,
   because JSON.stringify(undefined) returns the string "undefined" with no
   exception, and TextEncoder turns that into a plausible-looking 9 bytes.

FIELD NAMING: the secret key's Carmichael function is `lambda_` on the object
AND `lambda_` in the JSON. The masterplan's illustrative JSON (§4.10) shows
"lambda", but build spec §5.2 requires picking one spelling and never mixing;
`lambda_` is chosen because it avoids the Python keyword without needing a
process_value_in/out override. The secret key never leaves the server -- it is
not sent to the booth or to any verifier -- so the spelling has no interop
consequence.
"""

from helios.crypto import paillier as crypto_paillier
from helios.datatypes import LDObject, arrayOf


class PaillierObject(LDObject):
    WRAPPED_OBJ_CLASS = dict
    USE_JSON_LD = False


class PublicKey(PaillierObject):
    """
    A Paillier public key: {n, g}, plus {h, g_prime} under DJN §4.1.

    The §4.1 parameters are emitted ONLY when the key carries them, rather than
    being declared in FIELDS and serialized as nulls on a standard key. Two
    reasons, and the second is the load-bearing one:

    1. A standard key's serialization is then byte-for-byte what it was before
       §4.1 existed, so stored elections and the B8 ballot-size canary are
       unaffected.
    2. Presence IS the discriminator. PaillierPublicKey.uses_djn_41 tests for
       `h`, so a key that round-trips through the database comes back in the
       same mode it went in, with no separate boolean to drift out of sync with
       the values it describes.
    """
    WRAPPED_OBJ_CLASS = crypto_paillier.PaillierPublicKey
    FIELDS = ['n', 'g']
    STRUCTURED_FIELDS = {
        'n': 'core/BigInteger',
        'g': 'core/BigInteger'}

    # Serialized alongside FIELDS when present. Not in FIELDS itself, because
    # LDObject.loadDataFromDict indexes d[f] unconditionally and would raise
    # KeyError on every standard key.
    DJN41_FIELDS = ['h', 'g_prime']

    def toDict(self, complete=False):
        d = super(PublicKey, self).toDict(complete=complete)

        pk = self.wrapped_obj
        if getattr(pk, 'h', None) is not None:
            for f in self.DJN41_FIELDS:
                d[f] = str(getattr(pk, f))

        return d

    def loadDataFromDict(self, d):
        super(PublicKey, self).loadDataFromDict(d)

        for f in self.DJN41_FIELDS:
            value = d.get(f)
            setattr(self.wrapped_obj, f, int(value) if value else None)


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
