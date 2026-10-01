"""
Scheme-dispatch adapters for the ElGamal arm.

WHAT THIS MODULE IS, AND WHY IT IS SHAPED THIS WAY
--------------------------------------------------
helios/workflows/homomorphic.py named `algs` in nine places, all scheme-specific.
To host a second cryptosystem without duplicating the tallying algorithms, that
scheme-specific behaviour moves onto the public key object -- which
homomorphic.py already holds in every one of those scopes. After the move,
homomorphic.py contains ZERO references to `algs` or to any scheme name, which
is what makes the "identical pipeline" claim inspectable rather than argued.

The Paillier side of that interface lives naturally on PaillierPublicKey. The
ElGamal side has nowhere to live, because the experiment forbids editing
helios/crypto/algs.py and helios/crypto/elgamal.py -- not one line. So this
module attaches the ElGamal implementations onto those classes at import time.

THIS IS A MONKEY-PATCH, AND IT IS THE ONE PLACE THE DESIGN TRADES PURITY FOR THE
NO-EDIT RULE. A reviewer should see it, which is why it is an explicit module
with this docstring rather than a few lines tucked into an __init__.

Every method body below is COPIED VERBATIM from the call site it replaces, so
the refactor is behaviour-preserving by construction rather than by argument.
The line references are to the pre-refactor homomorphic.py. helios/fixtures/
elgamal_golden_ballot.json is the mechanical check: a fixed-seed ElGamal ballot
must serialize byte-identically across this change (test 15).

WHY BOTH CLASSES ARE PATCHED
----------------------------
Helios has two ElGamal lineages that have drifted apart. At runtime an
election's public_key deserializes into helios.crypto.elgamal.PublicKey (that is
legacy.EGPublicKey's WRAPPED_OBJ_CLASS), while homomorphic.py separately refers
to algs.EGPlaintext and algs.EG_disjunctive_challenge_generator in the same
function. Objects of both lineages coexist inside one ballot construction. Only
elgamal.PublicKey is strictly required here; algs.EGPublicKey is patched too so
that the interface holds whichever lineage a caller happens to be holding.
"""

from helios.crypto import algs, elgamal


# ---------------------------------------------------------------------------
# The interface homomorphic.py depends on
# ---------------------------------------------------------------------------

def _eg_generate_plaintexts(self, min=0, max=1):
  """
  Was EncryptedAnswer.generate_plaintexts (homomorphic.py:26-39).

  Builds g^0, g^1, ... rather than 0, 1, ... because ElGamal.encrypt refuses to
  encrypt zero -- elgamal.js throws "Can't encrypt 0 with El Gamal". Paillier
  encrypts zero natively, which is precisely why this method has to become
  scheme-aware instead of staying a shared expression.
  """
  plaintexts = []
  running_product = 1

  # run the product up to the min
  for i in range(max + 1):
    # if we're in the range, add it to the array
    if i >= min:
      plaintexts.append(algs.EGPlaintext(running_product, self))

    # next value in running product
    running_product = (running_product * self.g) % self.p

  return plaintexts


def _eg_random_randomness(self):
  """Was `algs.random.mpz_lt(pk.q)` (homomorphic.py:128).

  Note the exponent is drawn from Z_q with q of 256 bits, not from Z_p. That
  short exponent in a 2048-bit group is a large structural advantage for
  ElGamal and the single biggest term in the §5.1 cost model.
  """
  return algs.random.mpz_lt(self.q)


def _eg_combine_randomness(self, acc, r):
  """Was `randomness_sum = (randomness_sum + r) % pk.q` (homomorphic.py:138).

  ElGamal sums randomness; Paillier multiplies it mod n. Same line, different
  operation -- the one place the identical-control-flow claim needs a named
  abstraction rather than a shared expression.
  """
  return (acc + r) % self.q


def _eg_verify_decryption_proof(self, ciphertext, factor, proof,
                                challenge_generator):
  """
  Was the positional call in Tally.verify_decryption_proofs
  (homomorphic.py:401):

      proof.verify(public_key.g, answer_tally.alpha, public_key.y,
                   int(decryption_factors[q_num][a_num]),
                   public_key.p, public_key.q, challenge_generator)

  Deeply ElGamal-shaped -- it names alpha and y -- and so cannot be shared with
  a scheme whose decryption factor is the plaintext itself.
  """
  return proof.verify(self.g, ciphertext.alpha, self.y, int(factor),
                      self.p, self.q, challenge_generator)


def _eg_tally_decoder(self, num_tallied):
  """
  Was the DLogTable construction and lookup in Tally.decrypt_from_factors
  (homomorphic.py:415-416, 429).

  Returns a callable mapping a decrypted group element to its tally.

  Helios does NOT use baby-step giant-step. DLogTable.precompute walks
  g^0..g^N by repeated modular multiplication into a dict, so recovery is
  Theta(N) in the number of voters and O(1) per lookup -- and, importantly,
  INDEPENDENT of how votes are distributed. Paillier has no counterpart at all,
  which is why tally_decoder exists as a seam rather than the dlog table being
  referenced directly.

  DLogTable is imported lazily: helios/workflows/__init__.py imports this
  module, so a module-level import of homomorphic would close a cycle.
  """
  from helios.workflows.homomorphic import DLogTable

  dlog_table = DLogTable(base=self.g, modulus=self.p)
  dlog_table.precompute(num_tallied)
  return dlog_table.lookup


def _eg_disjunctive_challenge_generator(self):
  """Was `algs.EG_disjunctive_challenge_generator` (homomorphic.py:68, 80, 133, 150)."""
  return algs.EG_disjunctive_challenge_generator


def _eg_fiatshamir_challenge_generator(self):
  """Was `algs.EG_fiatshamir_challenge_generator` (models.py, Trustee.verify_decryption_proofs).

  The single-commitment form, used to verify decryption proofs. Not on the
  measured path, but on the verifiability path.
  """
  return algs.EG_fiatshamir_challenge_generator


def _eg_ciphertext_class(self):
  """Was `algs.EGCiphertext` in Tally._process_value_in (homomorphic.py:437)."""
  return algs.EGCiphertext


# ---------------------------------------------------------------------------
# Attachment
# ---------------------------------------------------------------------------

_METHODS = {
  'generate_plaintexts': _eg_generate_plaintexts,
  'random_randomness': _eg_random_randomness,
  'combine_randomness': _eg_combine_randomness,
  'verify_decryption_proof': _eg_verify_decryption_proof,
  'tally_decoder': _eg_tally_decoder,
}

_PROPERTIES = {
  'disjunctive_challenge_generator': _eg_disjunctive_challenge_generator,
  'fiatshamir_challenge_generator': _eg_fiatshamir_challenge_generator,
  'ciphertext_class': _eg_ciphertext_class,
}

# The additive identity for accumulating randomness. ElGamal sums, so 0;
# Paillier multiplies, so 1. homomorphic.py initialises from this rather than
# hardcoding 0.
_ATTRIBUTES = {
  'randomness_identity': 0,
  # Decryption passes through a discrete-log table: tally_decoder above builds
  # it. Read by Tally.decrypt_from_factors to decide what it times; the same
  # meaning as has_dlog in the workload harness's schemes.py. Paillier's key
  # declares False.
  'has_dlog': True,
  # Which datatype a trustee public key of this scheme serializes as. Read by
  # models.generate_trustee, which previously hardcoded 'legacy/EGPublicKey'.
  'public_key_datatype': 'legacy/EGPublicKey',
}

_TARGETS = (elgamal.PublicKey, algs.EGPublicKey)


def install():
  """
  Attach the interface. Idempotent, and never overwrites an existing attribute.

  The no-overwrite rule matters: if a future upstream Helios grows a real
  `generate_plaintexts` on its public key, this module must defer to it rather
  than silently shadow it -- a monkey-patch that clobbers is how an upstream
  bugfix gets undone without anyone noticing.
  """
  for target in _TARGETS:
    for name, fn in _METHODS.items():
      if not hasattr(target, name):
        setattr(target, name, fn)

    for name, fn in _PROPERTIES.items():
      if not hasattr(target, name):
        setattr(target, name, property(fn))

    for name, value in _ATTRIBUTES.items():
      if not hasattr(target, name):
        setattr(target, name, value)


# Also give the Cryptosystem the two attributes models.generate_trustee reads,
# so that call site can stop hardcoding ElGamal specifics.
def install_cryptosystem():
  if not hasattr(elgamal.Cryptosystem, 'public_key_datatype'):
    elgamal.Cryptosystem.public_key_datatype = 'legacy/EGPublicKey'
  if not hasattr(elgamal.Cryptosystem, 'dlog_challenge_generator'):
    elgamal.Cryptosystem.dlog_challenge_generator = staticmethod(
      algs.DLog_challenge_generator)
  if not hasattr(algs.ElGamal, 'public_key_datatype'):
    algs.ElGamal.public_key_datatype = 'legacy/EGPublicKey'
  if not hasattr(algs.ElGamal, 'dlog_challenge_generator'):
    algs.ElGamal.dlog_challenge_generator = staticmethod(
      algs.DLog_challenge_generator)


install()
install_cryptosystem()
