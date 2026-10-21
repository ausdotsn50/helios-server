"""
Scheme-dispatch adapters
"""

from helios.crypto import algs, elgamal


# ---------------------------------------------------------------------------
# ElGamal half of shared interface
# ---------------------------------------------------------------------------

def _eg_generate_plaintexts(self, min=0, max=1):
  """
  Was EncryptedAnswer.generate_plaintexts

  Builds g^0, g^1, ... rather than 0, 1, ... for ElGamal
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
  """Was `algs.random.mpz_lt(pk.q)`

  Note the exponent is drawn from Z_q with q of 256 bits, not from Z_p.
  """
  return algs.random.mpz_lt(self.q)


def _eg_combine_randomness(self, acc, r):
  """Was `randomness_sum = (randomness_sum + r) % pk.q`
  """
  return (acc + r) % self.q


def _eg_verify_decryption_proof(self, ciphertext, factor, proof,
                                challenge_generator):
  """
  Was the positional call in Tally.verify_decryption_proofs

      proof.verify(public_key.g, answer_tally.alpha, public_key.y,
                   int(decryption_factors[q_num][a_num]),
                   public_key.p, public_key.q, challenge_generator)
  """
  return proof.verify(self.g, ciphertext.alpha, self.y, int(factor),
                      self.p, self.q, challenge_generator)


def _eg_tally_decoder(self, num_tallied):
  """
  Was the DLogTable construction and lookup in Tally.decrypt_from_factors

  Returns a callable mapping a decrypted group element to its tally.

  DLogTable is imported lazily: helios/workflows/__init__.py imports this
  module, so a module-level import of homomorphic would close a cycle.
  """
  from helios.workflows.homomorphic import DLogTable

  dlog_table = DLogTable(base=self.g, modulus=self.p)
  dlog_table.precompute(num_tallied)
  return dlog_table.lookup


def _eg_disjunctive_challenge_generator(self):
  return algs.EG_disjunctive_challenge_generator


def _eg_fiatshamir_challenge_generator(self):
  """Was `algs.EG_fiatshamir_challenge_generator`

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
  # it. Read by Tally.decrypt_from_factors to decide what it times. Paillier's
  # key declares False.
  'has_dlog': True,
  # Which datatype a trustee public key of this scheme serializes as. Read by
  # models.generate_trustee, which previously hardcoded 'legacy/EGPublicKey'.
  'public_key_datatype': 'legacy/EGPublicKey',
}

_TARGETS = (elgamal.PublicKey, algs.EGPublicKey)


def install():
  """
  Attach the interface. Idempotent, and never overwrites an existing attribute.
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
