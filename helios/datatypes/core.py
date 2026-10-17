"""
core data types
"""

from helios.datatypes import LDObject

class BigInteger(LDObject):
    """
    A big integer is an integer serialized as a string.
    We may want to b64 encode here soon.
    """
    WRAPPED_OBJ_CLASS = int

    def toDict(self, complete=False):
        # `is not None`, not truthiness: 0 is a legitimate big integer and must
        # serialize as "0". Under ElGamal this was harmless -- decryption factors
        # are group elements in [1, p) and are never zero -- but a Paillier
        # decryption factor IS the plaintext tally, so a candidate with no votes
        # produces exactly 0. Trustee.decryption_factors is typed
        # arrayOf(arrayOf('core/BigInteger')), so under the old guard a zero
        # tally round-tripped as null and the result was wrong for precisely the
        # candidates nobody voted for.
        if self.wrapped_obj is not None:
            return str(self.wrapped_obj)
        else:
            return None

    def loadDataFromDict(self, d):
        "take a string and cast it to an int -- which is a big int too"
        self.wrapped_obj = int(d)

class Timestamp(LDObject):
    def toDict(self, complete=False):
        if self.wrapped_obj:
            return str(self.wrapped_obj)
        else:
            return None
    
