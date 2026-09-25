"""
Paillier cryptosystem for the Helios Voting System.

The Paillier arm of "System-Level Performance Comparison of Paillier and
Exponential ElGamal using the Helios Voting System" (A. D. Almazan, UP Visayas
Tacloban). Specified by PAILLIER_MASTERPLAN.md §4 and PAILLIER_BUILD_SPEC.md §2.

This module carries the WHOLE surface deliberately. Helios has two ElGamal
lineages that have drifted apart -- helios/crypto/algs.py (EGPublicKey,
EGCiphertext, ...) used by models.py and workflows/homomorphic.py, and
helios/crypto/elgamal.py (PublicKey, Ciphertext, ...) used by
datatypes/legacy.py as every WRAPPED_OBJ_CLASS. Objects of both lineages coexist
inside a single ballot construction and it works only because they are duck-type
compatible. Mirroring that split would produce a Paillier module that either the
datatypes layer never instantiates or homomorphic.py cannot call. One module,
pointed at by the new datatypes, avoids the whole problem.

Parameters (build spec §2): k = 1024 bits per prime, so |n| = 2048 and
|n^2| = 4096, matching ElGamal's 2048-bit p. Challenge width t = 160, matching
Helios's existing SHA-1 generator. L(x) = (x-1)/n.
"""

import math

from Crypto.Hash import SHA1
from Crypto.Util import number

from helios.crypto.utils import random

# Bits per prime. |n| = 2*KEY_SIZE = 2048, matching ElGamal's 2048-bit p, so the
# two arms are compared at equal modulus width.
DEFAULT_KEY_SIZE = 1024

# Minimum modulus width accepted by validate_pk_params. Tests construct keys far
# below this deliberately and never route them through validation.
MIN_MODULUS_BITS = 2048


# ---------------------------------------------------------------------------
# DJN §4.1 — the alternative encryption function
# ---------------------------------------------------------------------------
#
# Standard Paillier encrypts with  Enc(m, v) = (1 + m*n) * v^n mod n^2,  and the
# exponent n is 2048 bits because it IS the modulus: the blinding factor must be
# a random n-th residue, and the n-th residues have index n in Z*_{n^2}, which
# is also what makes the message space Z_n. The exponent is not a tunable
# security parameter, and it cannot be reduced (n < lambda(n^2) = n*lambda(n)).
#
# DJN §4.1 buys a short exponent by fixing a public base:
#
#     h = g'^(2n) mod n^2   for random g' in Z*_n
#     Enc(m, r) = (1 + m*n) * h^r mod n^2,   r <-$ [0, 2^DJN41_EXPONENT_BITS)
#
# THE KEY PROPERTY, and the reason this costs no new proof theory: h is ITSELF
# an n-th residue by construction, so
#
#     h^r = (g'^(2n))^r = (g'^(2r))^n
#
# is still an n-th power, and the voter can compute its n-th root cheaply as
# v = g'^(2r) mod n -- one short-exponent exponentiation at a 2048-bit modulus.
# So Pi_root applies UNCHANGED: same statement, same prover, same simulator,
# same verifier, same serialization, same ballot size. Only the ciphertext's
# blinding factor is produced differently.
#
# (The reduction mod n is safe: for any integer x, (x mod n)^n = x^n (mod n^2),
# because the cross terms of the binomial expansion all carry n^2. Test
# DJN41Tests.test_witness_is_a_valid_nth_root checks this directly.)
#
# COST: the ciphertext exponentiation drops from (4096-bit modulus, 2048-bit
# exponent) to (4096, DJN41_EXPONENT_BITS), plus one (2048, DJN41_EXPONENT_BITS)
# for the witness. Measured ~3.1x on the ciphertext. The reported
# encryption metric improves far less (~1.28x) because an EncryptedAnswer is
# dominated by its proofs, not its ciphertexts -- see PAILLIER_MASTERPLAN.md §5.
#
# SECURITY: this needs an assumption BEYOND decisional composite residuosity --
# that h^r for short r is indistinguishable from a uniform n-th residue. That
# assumption, and not the proof system, is the real reason to think twice about
# enabling this. It is why the behaviour is a flag rather than a replacement:
# the standard path stays available, is the default, and remains the one checked
# against the external `phe` oracle in test 14.
#
# Cite: Damgard, Jurik, Nielsen (2010) §4.1.

# Bit length of the short exponent r.
#
# CONSERVATIVE PLACEHOLDER. DJN discuss a short exponent on the order of 2t for
# a security parameter t, which would put this nearer 256. 512 is chosen for
# margin, and the value is deliberately a named constant so the ablation can
# sweep it. VERIFY AGAINST THE PAPER before quoting a figure derived from it in
# the manuscript.
DJN41_EXPONENT_BITS = 512


# ---------------------------------------------------------------------------
# Randomness (build spec §2.2)
# ---------------------------------------------------------------------------
#
# Helios's own sampler is biased and must not be copied. helios/crypto/utils.py:
#
#     def random_mpz_lt(maximum, strong_random=random):
#         n_bits = int(math.floor(math.log(maximum, 2)))
#         res = strong_random.getrandbits(n_bits)
#         while res >= maximum:
#             res = strong_random.getrandbits(n_bits)
#         return res
#
# With floor(log2(maximum)) bits the draw can never reach `maximum`, so the
# rejection loop never fires and the output is uniform on
# [0, 2^floor(log2 max)) rather than [0, maximum). For Helios's 256-bit q that
# makes roughly the top 5.5% of Z_q unreachable. algs.py opens with
# "FIXME: improve random number generation", so this is known-rough ground.
#
# Sampling cost is negligible either way, so using a correct sampler here costs
# nothing measurable and avoids building a known bias into the new arm. The
# ElGamal path keeps its own sampler untouched -- fixing it would modify the
# control arm, which the experiment forbids.

def random_lt(maximum, strong_random=random):
  """Uniform on [0, maximum). Correct rejection sampling."""
  n_bits = maximum.bit_length()
  res = strong_random.getrandbits(n_bits)
  while res >= maximum:
    res = strong_random.getrandbits(n_bits)
  return res


def random_z_star_n(n, strong_random=random):
  """
  Uniform on Z*_n.

  The gcd check will essentially never fire -- the rejection probability is
  1/p + 1/q, about 2^-1023 at this key size. It is kept because a v sharing a
  factor with n would leak the factorization, and a silent failure there is
  total.
  """
  while True:
    v = random_lt(n, strong_random)
    if v > 0 and math.gcd(v, n) == 1:
      return v


# ---------------------------------------------------------------------------
# Challenge generation (build spec §2.9)
# ---------------------------------------------------------------------------
#
# This is where cross-language builds fail silently, so it is specified once,
# implemented twice, and tested before either proof layer exists (milestone B1).
# A mismatch in hash-input formatting means every ballot verifies locally in the
# browser and every cast fails on the server, with the symptom far from the
# cause.
#
# The JavaScript twin is Paillier.disjunctive_challenge_generator in
# heliosbooth/js/jscrypto/paillier.js. Invariants that must hold in BOTH:
#
#   - Radix 10, no leading zeros, no sign. All values are positive.
#   - Separator is one ASCII comma. No spaces, no trailing comma.
#   - UTF-8 encoding of an ASCII-only string.
#   - Canonicalise before stringifying: a reduced mod n^2, z mod n,
#     e mod 2^160. Two implementations that disagree only about whether a value
#     was reduced produce different hashes.
#
# t = 160 rather than 256: extraction requires 2^t < the smallest prime factor
# of n, which at 1024-bit primes leaves ~864 bits of margin. Reusing Helios's
# SHA-1 generator therefore satisfies the soundness bound AND holds the hash
# function constant across both arms, removing a hashing-cost difference from
# the comparison. (This supersedes IMPLEMENTATION_SPEC.md §2.2.2, which
# specified SHA-256; masterplan decision 6.)

CHALLENGE_BITS = 160
CHALLENGE_MODULUS = 1 << CHALLENGE_BITS


def paillier_disjunctive_challenge_generator(commitments):
  """
  Fiat-Shamir challenge over a list of Pi_root commitments.

  Mirrors algs.EG_disjunctive_challenge_generator, which hashes the same
  comma-joined decimal form. The difference is structural rather than
  stylistic: a Chaum-Pedersen commitment is the pair (A, B) and contributes two
  strings, while a Pi_root commitment is a single value and contributes one.

  :param commitments: list of int, the a_j
  :returns: int in [0, 2^160)
  """
  string_to_hash = ",".join(str(a) for a in commitments)
  return int(SHA1.new(bytes(string_to_hash, 'utf-8')).hexdigest(), 16) % CHALLENGE_MODULUS


def paillier_fiatshamir_challenge_generator(commitment):
  """
  Single-commitment case, used by the proof of correct decryption (§2.8).

  Wraps the disjunctive generator with a one-element list, exactly as
  EG_fiatshamir_challenge_generator wraps EG_disjunctive_challenge_generator.
  """
  return paillier_disjunctive_challenge_generator([commitment])


# ---------------------------------------------------------------------------
# Cryptosystem (build spec §2.1, §4.1)
# ---------------------------------------------------------------------------

class Paillier:
  """
  Counterpart of elgamal.Cryptosystem.

  The structural asymmetry worth naming up front: ElGamal's group parameters
  (p, q, g) are hardcoded constants in views.py, so keygen is one exponentiation
  in a fixed group. Paillier has no fixed public parameters -- every keypair
  requires two fresh 1024-bit primes. That gap is architectural rather than
  algorithmic, and the manuscript reports it as such rather than as a
  like-for-like algorithmic comparison.
  """

  def __init__(self, key_size=DEFAULT_KEY_SIZE, use_djn_41=False):
    self.key_size = key_size

    # Whether generated keys carry the DJN §4.1 short-exponent parameters.
    #
    # Default OFF. The standard encryption function is the one whose security
    # rests on decisional composite residuosity alone, and the one test 14
    # cross-checks against the external `phe` oracle. Enabling this is an
    # explicit choice to widen the assumption in exchange for ~3.1x on
    # ciphertext generation.
    self.use_djn_41 = use_djn_41

  # --- surface models.generate_trustee reads (build spec §4.3) -------------

  # Which datatype a trustee public key of this scheme serializes as.
  public_key_datatype = 'paillier/PublicKey'

  # Paillier generates no trustee proof of knowledge of the secret key, so
  # there is no challenge generator for one. See PaillierSecretKey.prove_sk.
  dlog_challenge_generator = None

  def generate_keypair(self):
    keypair = PaillierKeyPair()
    keypair.generate(self.key_size, use_djn_41=self.use_djn_41)
    return keypair

  def toJSONDict(self):
    return {'key_size': str(self.key_size),
            'use_djn_41': self.use_djn_41}

  @classmethod
  def fromJSONDict(cls, d):
    return cls(key_size=int(d['key_size']),
               use_djn_41=bool(d.get('use_djn_41', False)))


class PaillierKeyPair:
  """Counterpart of elgamal.KeyPair."""

  def __init__(self):
    self.pk = PaillierPublicKey()
    self.sk = PaillierSecretKey()

  def generate(self, key_size=DEFAULT_KEY_SIZE, use_djn_41=False):
    """
    Build a keypair (build spec §2.1).

        p, q  <- distinct random primes, exactly `key_size` bits each
        n     =  p*q
        g     =  1 + n
        lambda=  lcm(p-1, q-1)
        mu    =  lambda^-1 mod n

    mu reduces to a modular inverse rather than the general
    (L(g^lambda mod n^2))^-1 because g = 1+n gives g^lambda = 1 + lambda*n
    (mod n^2), hence L(g^lambda) = lambda. Derived, not quoted -- test 13
    computes it both ways and asserts equality.

    getStrongPrime rather than getPrime: it additionally ensures p-1 and p+1
    carry a large prime factor. That is the standard choice for an RSA-shaped
    modulus, and since key generation is one of the reported metrics the choice
    is recorded here rather than left implicit -- it makes keygen measurably
    slower than naive prime search would be, and comparably safer.
    """
    p = number.getStrongPrime(key_size)
    q = number.getStrongPrime(key_size)
    while q == p:
      q = number.getStrongPrime(key_size)

    self._assign(p, q, use_djn_41=use_djn_41)
    return self

  def _assign(self, p, q, use_djn_41=False):
    """Shared by generate() and the fixed-prime construction used in tests."""
    n = p * q

    self.pk.n = n
    self.pk.g = n + 1

    if use_djn_41:
      # h = g'^(2n) mod n^2 for random g'. Both are public: h is derived from g'
      # by a public computation, so publishing g' reveals nothing further, and
      # the voter NEEDS g' to compute the Pi_root witness g'^(2r) mod n.
      #
      # This costs one extra (4096-bit modulus, 2048-bit exponent)
      # exponentiation at key generation -- roughly +30% on keygen time, paid
      # once per election against a per-ballot saving.
      n2 = n * n
      self.pk.g_prime = random_z_star_n(n)
      self.pk.h = pow(self.pk.g_prime, 2 * n, n2)

    self.sk.p = p
    self.sk.q = q
    self.sk.lambda_ = math.lcm(p - 1, q - 1)
    self.sk.mu = number.inverse(self.sk.lambda_, n)
    self.sk.public_key = self.pk

    if p == q:
      raise Exception("p and q must be distinct")
    if math.gcd(self.sk.lambda_, n) != 1:
      raise Exception("gcd(lambda, n) != 1")

    return self

  @classmethod
  def from_primes(cls, p, q, use_djn_41=False):
    """
    Construct from fixed primes.

    Used by the test suite -- both for small keys that keep the suite fast, and
    for the deterministic (p, q, m, v) vectors checked against the external
    oracle in test 14.
    """
    kp = cls()
    return kp._assign(p, q, use_djn_41=use_djn_41)


class PaillierPublicKey:
  """Counterpart of elgamal.PublicKey / algs.EGPublicKey."""

  # Declared on the wrapped object so LDObject.instantiate routes it to the
  # Paillier serializer even when the field's static type hint says ElGamal.
  # See helios/datatypes/__init__.py.
  datatype = 'paillier/PublicKey'

  def __init__(self, n=None, g=None, h=None, g_prime=None):
    self.n = n
    self.g = g

    # DJN §4.1 parameters. Both None on a standard key; the presence of `h` is
    # what puts this key in short-exponent mode, so the mode is self-describing
    # and survives serialization without a separate flag to keep in sync.
    self.h = h
    self.g_prime = g_prime

  @property
  def n2(self):
    """Derived, never serialized."""
    return self.n * self.n

  @property
  def uses_djn_41(self):
    """True when this key carries the DJN §4.1 short-exponent parameters."""
    return self.h is not None

  # --- encryption (build spec §2.3) ---------------------------------------

  def encrypt_with_r(self, plaintext, r, encode_message=False):
    """
        Enc(m, v) = (1 + m*n) * v^n  mod n^2

    The message component is ONE MULTIPLICATION, never an exponentiation. That
    is the mandated (1+n)^m = 1+mn identity: since (1+n)^m expands to
    1 + mn + C(m,2)n^2 + ... and every term from the third on carries n^2, the
    whole tail vanishes mod n^2. Only v^n costs. This is one of the few places
    Paillier is structurally cheaper than ElGamal, which encodes its message as
    g^m and pays a second exponentiation for it.

    `encode_message` exists for signature parity with
    EGPublicKey.encrypt_with_r, where it selects subgroup encoding. That has no
    Paillier meaning -- Paillier encrypts 0 natively and needs no encoding -- so
    it is accepted and refused rather than silently ignored.
    """
    if encode_message:
      raise Exception(
        "encode_message has no meaning under Paillier: the plaintext is the "
        "integer itself, with no subgroup encoding. The parameter exists only "
        "for signature parity with EGPublicKey.encrypt_with_r.")

    m = plaintext.m if hasattr(plaintext, 'm') else plaintext
    n, n2 = self.n, self.n2

    if self.uses_djn_41:
      # DJN §4.1: r is an EXPONENT against the fixed base h, not a base raised
      # to n. The exponentiation is (4096-bit modulus, ~512-bit exponent)
      # instead of (4096, 2048).
      blinding = pow(self.h, r, n2)
    else:
      blinding = pow(r, n, n2)

    return PaillierCiphertext(((1 + m * n) * blinding) % n2, self)

  def encrypt_return_r(self, plaintext):
    """
    Encrypt and hand back the randomness, which the proofs need as witness.

    Draws through random_randomness() rather than sampling Z*_n directly: under
    DJN §4.1 the randomness is a short EXPONENT, and sampling a full-width base
    here would silently produce a correct-but-unoptimized ciphertext -- self
    consistent, verifying, and slower than the standard path it was meant to
    beat. Nothing would have failed; the optimization simply would not have
    happened.
    """
    r = self.random_randomness()
    return [self.encrypt_with_r(plaintext, r), r]

  def encrypt(self, plaintext):
    return self.encrypt_return_r(plaintext)[0]

  # --- trustee-key combination (build spec §4.6, enforcement point 1) ------

  def __mul__(self, other):
    """
    Refuse to combine Paillier trustee keys.

    ElGamal-Helios combines trustee keys at freeze (models.py:613-618) because
    every trustee generates a secret in the SAME hardcoded group, so y = prod(yi)
    corresponds to x = sum(xi). Note this is not distributed key generation:
    there is no shared secret, no polynomial and no secret sharing, and both
    algs.py:530 and elgamal.py:420 say "For now, no support for threshold".

    Paillier has no shared group to generate into. Trustees would produce
    unrelated moduli n_i, and no operation combines RSA-shaped moduli into a
    joint public key. Paillier's multi-party counterpart is the threshold
    variant, which needs genuine DKG -- out of scope. So single-trustee follows
    from the cryptosystem's structure rather than from convenience.

    The 0/1 cases are the identities homomorphic_sum relies on and are kept.
    """
    if other == 0 or other == 1:
      return self

    raise NotImplementedError(
      "Paillier trustee keys cannot be combined; threshold Paillier requires "
      "DKG, which is out of scope. See PAILLIER_BUILD_SPEC.md §4.6.")

  # --- the scheme-dispatch interface homomorphic.py depends on ------------
  #
  # Counterpart of helios/crypto/scheme_adapters.py's ElGamal side. Keeping
  # these on the public key is what lets workflows/homomorphic.py hold zero
  # references to any scheme.

  def generate_plaintexts(self, min=0, max=1):
    """
    The candidate plaintexts for a disjunctive proof: the integers themselves.

    ElGamal builds g^0, g^1, ... because ElGamal.encrypt refuses to encrypt
    zero. Paillier encrypts zero natively, so no encoding is needed and m is
    the integer.
    """
    return [PaillierPlaintext(i, self) for i in range(min, max + 1)]

  def random_randomness(self):
    """
    Fresh encryption randomness.

    Standard: a base, uniform on Z*_n.
    DJN §4.1: an exponent, uniform on [0, 2^DJN41_EXPONENT_BITS).
    """
    if self.uses_djn_41:
      return random_lt(1 << DJN41_EXPONENT_BITS)
    return random_z_star_n(self.n)

  def combine_randomness(self, acc, r):
    """
    How the overall proof's combined witness is accumulated.

    Standard: MULTIPLICATIVE. V = prod(v_i) mod n is correct because
    (prod v_i)^n = prod(v_i^n) mod n^2.

    DJN §4.1: ADDITIVE, because the randomness is an exponent and
    h^r1 * h^r2 = h^(r1+r2). Note there is no modulus: reducing would require
    ord(h), which divides lambda(n) and is secret. The sum stays small anyway --
    222 slots of ~512-bit exponents is ~520 bits.

    So under §4.1 this coincides with ElGamal's additive form, which is a mild
    simplification of the identical-pipeline story rather than a complication.
    """
    if self.uses_djn_41:
      return acc + r
    return (acc * r) % self.n

  @property
  def randomness_identity(self):
    """Multiplicative 1 for the standard path, additive 0 under §4.1."""
    return 0 if self.uses_djn_41 else 1

  def proof_witness(self, randomness):
    """
    The Pi_root witness v with u = v^n mod n^2, from the stored randomness.

    Standard: the randomness IS the witness.
    DJN §4.1: the randomness is an exponent r, and the witness is
    v = g'^(2r) mod n -- one short-exponent exponentiation. This is the step
    that keeps the proof system unchanged: h is an n-th residue, so h^r is an
    n-th power and this is its root.
    """
    if self.uses_djn_41:
      return pow(self.g_prime, 2 * randomness, self.n)
    return randomness

  def tally_decoder(self, num_tallied):
    """
    Identity. There is no discrete-log stage to undo.

    ElGamal returns DLogTable.lookup after a Theta(N) precompute; single-trustee
    Paillier decryption already yields the plaintext, so the decoder is a
    pass-through. Making that a visible seam rather than a hidden branch is the
    point: the absence of the dlog stage is one of the structural differences
    the study exists to characterise, and the harness reports it as an absent
    metric rather than a zero.
    """
    return lambda raw_value: raw_value

  @property
  def disjunctive_challenge_generator(self):
    return paillier_disjunctive_challenge_generator

  @property
  def fiatshamir_challenge_generator(self):
    """Single-commitment form, used to verify decryption proofs."""
    return paillier_fiatshamir_challenge_generator

  @property
  def ciphertext_class(self):
    return PaillierCiphertext

  # --- decryption-proof verification (build spec §2.8) --------------------

  def verify_decryption_proof(self, ciphertext, factor, proof,
                              challenge_generator=None):
    """
    Public verification that `factor` really is the plaintext of `ciphertext`.

        e == challenge_generator([a])
        z^n == a * (c * (1 - m*n))^e   (mod n^2)

    Lives on the public key rather than being spelled out at the call site so
    that Tally.verify_decryption_proofs can stay scheme-agnostic. The ElGamal
    equivalent -- proof.verify(pk.g, tally.alpha, pk.y, factor, pk.p, pk.q, ...)
    -- is deeply ElGamal-shaped and cannot be shared.
    """
    if challenge_generator is None:
      challenge_generator = paillier_fiatshamir_challenge_generator

    c = ciphertext.c if hasattr(ciphertext, 'c') else ciphertext
    u = (c * (1 - int(factor) * self.n)) % self.n2

    return proof.verify(u, self, challenge_generator)

  # --- validation (mirrors EGPublicKey.validate_pk_params) ----------------

  def validate_pk_params(self):
    if self.n is None or self.g is None:
      raise Exception("n and g must be present.")

    if self.n <= 0 or self.n % 2 == 0:
      raise Exception("n must be a positive odd integer.")

    if self.g != self.n + 1:
      raise Exception("g must equal n+1.")

    if number.size(self.n) < MIN_MODULUS_BITS:
      raise Exception(
        "n of insufficient length. Should be %s bits or greater."
        % MIN_MODULUS_BITS)

    if number.isPrime(self.n):
      raise Exception("n must be composite.")

    if self.uses_djn_41:
      if self.g_prime is None:
        raise Exception("h present without g_prime: the voter cannot derive "
                        "the proof witness without g_prime.")
      if not (0 < self.h < self.n2):
        raise Exception("h out of range.")
      if math.gcd(self.h, self.n) != 1:
        raise Exception("h is not a unit mod n.")
      # h must be an n-th residue, or h^r is not an n-th power and no Pi_root
      # witness exists. Checking the construction directly is cheap relative to
      # key generation and catches a malformed or substituted key.
      if pow(self.g_prime, 2 * self.n, self.n2) != self.h:
        raise Exception("h != g_prime^(2n) mod n^2; h is not a verifiable "
                        "n-th residue and ballot proofs would be unprovable.")

  # --- serialization (build spec §5.3) ------------------------------------

  def to_dict(self):
    # g is serialized even though it equals n+1: it costs nothing, mirrors
    # EGPublicKey's four redundant fields, and gives validate_pk_params
    # something to check.
    #
    # h and g_prime appear ONLY on a DJN §4.1 key. Their presence is what puts
    # a deserialized key into short-exponent mode, so the two representations
    # stay distinguishable without a separate flag that could drift out of sync
    # with the values it describes.
    d = {'n': str(self.n), 'g': str(self.g)}
    if self.uses_djn_41:
      d['h'] = str(self.h)
      d['g_prime'] = str(self.g_prime)
    return d

  toJSONDict = to_dict

  @classmethod
  def from_dict(cls, d):
    pk = cls(n=int(d['n']), g=int(d['g']),
             h=int(d['h']) if d.get('h') else None,
             g_prime=int(d['g_prime']) if d.get('g_prime') else None)
    pk.validate_pk_params()
    return pk

  fromJSONDict = from_dict

  def __eq__(self, other):
    if other is None or not isinstance(other, PaillierPublicKey):
      return False
    return (self.n == other.n and self.g == other.g
            and self.h == other.h and self.g_prime == other.g_prime)

  def __ne__(self, other):
    return not self.__eq__(other)


class PaillierSecretKey:
  """Counterpart of elgamal.SecretKey / algs.EGSecretKey."""

  datatype = 'paillier/SecretKey'

  def __init__(self, p=None, q=None, lambda_=None, mu=None, public_key=None):
    self.p = p
    self.q = q
    self.lambda_ = lambda_
    self.mu = mu
    self.public_key = public_key
    self._h_p = self._h_q = self._p_inv = self._p2_inv_q2 = None

  # Whether the decryption PROOF uses CRT. Decryption itself always does --
  # see decrypt_factor. Kept separate and switchable so B10 can measure the
  # two independently rather than reporting one number for both.
  use_crt_for_proofs = True

  @property
  def pk(self):
    """Alias, as elgamal.SecretKey has."""
    return self.public_key

  @pk.setter
  def pk(self, value):
    self.public_key = value

  # --- CRT precomputation (build spec §2.4) -------------------------------

  # The CRT constants are derived state, and they are computed LAZILY rather
  # than in __init__.
  #
  # The reason is the deserialization path: LDObject.loadDataFromDict builds a
  # bare PaillierSecretKey() and then assigns p, q, lambda_ and mu one at a
  # time, so a secret key reloaded from the database never passes through a
  # constructor that has p and q available. Precomputing eagerly gave a key that
  # worked in memory and raised AttributeError on h_p after a round-trip -- an
  # error that only appears once the election is real.
  #
  # Cost is unchanged in the measured path: the constants are three modular
  # inverses computed once per key on first use and cached, against ~52 ms per
  # CRT decryption. The first decryption of a run carries them.

  @property
  def h_p(self):
    if self._h_p is None:
      self._precompute_crt()
    return self._h_p

  @property
  def h_q(self):
    if self._h_q is None:
      self._precompute_crt()
    return self._h_q

  @property
  def p_inv(self):
    if self._p_inv is None:
      self._precompute_crt()
    return self._p_inv

  @property
  def p2_inv_q2(self):
    if self._p2_inv_q2 is None:
      self._precompute_crt()
    return self._p2_inv_q2

  # --- CRT exponentiation, available only to the factorization holder ------
  #
  # These accelerate the DECRYPTION PROOF, which is distinct from decryption
  # itself (already CRT-accelerated in decrypt_factor). Masterplan §4.7:
  # "Steps 3 and 4's commitment are both CRT-accelerable, since only the
  # trustee runs them."
  #
  # Why this is worth having: of ~307 ms per answer slot in
  # decryption_factor_and_proof, ~250 ms sat in exactly two exponentiations
  # that the trustee -- and ONLY the trustee -- can split over p and q. Leaving
  # them unaccelerated measured Paillier decryption at ~15x ElGamal where a
  # fair implementation shows ~6x.
  #
  # That matters more than a typical optimization because of the exposure
  # argument in masterplan §6.2: five of the six reported metrics are
  # structurally immune to the "you under-optimized Paillier" objection,
  # because the party doing the work does not hold the factorization. The
  # voter cannot use CRT; the aggregating server cannot; a public verifier
  # cannot. Decryption is the ONE metric where the objection has a real target,
  # so it is the one place the implementation must not leave anything on the
  # table.

  def crt_pow_n(self, base, exponent):
    """
    base^exponent mod n, via p and q.

    Two exponentiations at a 1024-bit modulus replace one at 2048 bits, with
    the exponent reduced mod (p-1) and (q-1) by Fermat. Valid for any base
    coprime to n, which every value reaching here is.
    """
    p, q = self.p, self.q

    m_p = pow(base % p, exponent % (p - 1), p)
    m_q = pow(base % q, exponent % (q - 1), q)

    return m_p + p * (((m_q - m_p) * self.p_inv) % q)

  def crt_pow_n2(self, base, exponent):
    """
    base^exponent mod n^2, via p^2 and q^2.

    Two exponentiations at a 2048-bit modulus replace one at 4096 bits. The
    exponent reduces mod lambda(p^2) = p(p-1) and lambda(q^2) = q(q-1) rather
    than mod (p-1) -- the group Z*_{p^2} has order p(p-1), not p-1, and using
    the smaller modulus here would produce a wrong answer that still looks
    plausible.
    """
    p, q = self.p, self.q
    p2, q2 = p * p, q * q

    m_p = pow(base % p2, exponent % (p * (p - 1)), p2)
    m_q = pow(base % q2, exponent % (q * (q - 1)), q2)

    return m_p + p2 * (((m_q - m_p) * self.p2_inv_q2) % q2)

  def _precompute_crt(self):
    """
    Precompute the per-key CRT constants.

    DJN §4.2 gives one sentence -- the standard trick "can also be used here
    with the moduli p^j and q^j" -- with no precomputation and no recombination
    step. What follows is derived from the mathematics and validated against phe
    (test 14). Do not cite DJN for the algorithm; cite it only for CRT being
    conventional practice.

        h_p = L_p(g^(p-1) mod p^2)^-1 mod p = (-q)^-1 mod p
        h_q = L_q(g^(q-1) mod q^2)^-1 mod q = (-p)^-1 mod q

    The closed forms hold because (1+pq)^(p-1) = 1 + (p-1)pq (mod p^2): every
    higher binomial term carries (pq)^2, which is 0 mod p^2. Hence
    L_p(g^(p-1)) = (p-1)q = -q (mod p). Test 13 computes h_p both ways and
    asserts equality, which is a free check that the derivation and the code
    agree.
    """
    p, q = self.p, self.q
    if p is None or q is None:
      raise Exception("cannot derive CRT constants without p and q")

    self._h_p = number.inverse((-q) % p, p)
    self._h_q = number.inverse((-p) % q, q)
    self._p_inv = number.inverse(p, q)

    # For CRT exponentiation modulo n^2 = p^2 * q^2 (see crt_pow_n2).
    self._p2_inv_q2 = number.inverse((p * p) % (q * q), q * q)

  # --- decryption (build spec §2.4) ---------------------------------------

  def decrypt_no_crt(self, ciphertext):
    """
        Dec(c) = L(c^lambda mod n^2) * mu  mod n

    One exponentiation at a 4096-bit modulus with a 2048-bit exponent. Kept
    alongside the CRT path as an ablation target (build spec §B10): the
    difference between the two is what CRT is worth, predicted ~3.9x.
    """
    n = self.public_key.n
    n2 = self.public_key.n2
    c = ciphertext.c if hasattr(ciphertext, 'c') else ciphertext

    x = pow(c, self.lambda_, n2)
    return ((x - 1) // n * self.mu) % n

  def decrypt_factor(self, ciphertext):
    """
        m_p = L_p(c^(p-1) mod p^2) * h_p  mod p
        m_q = L_q(c^(q-1) mod q^2) * h_q  mod q
        m   = m_p + p * ((m_q - m_p) * p_inv mod q)          (Garner)

    Two exponentiations at a 2048-bit modulus with 1024-bit exponents, replacing
    one at 4096 bits with a 2048-bit exponent.

    Valid because every tally satisfies m < n. CRT is available ONLY to the
    party holding p and q -- not the voter, not the aggregating server, not a
    public verifier -- which is why it affects exactly one of the six reported
    metrics.
    """
    p, q = self.p, self.q
    c = ciphertext.c if hasattr(ciphertext, 'c') else ciphertext

    m_p = ((pow(c, p - 1, p * p) - 1) // p * self.h_p) % p
    m_q = ((pow(c, q - 1, q * q) - 1) // q * self.h_q) % q

    return m_p + p * (((m_q - m_p) * self.p_inv) % q)

  def decryption_factor(self, ciphertext):
    """
    THE SANCTIONED DIVERGENCE (masterplan §3.3).

    ElGamal-Helios decrypts in two steps: each trustee publishes alpha^x, the
    factors are combined, and DLogTable recovers the exponent. Single-trustee
    Paillier yields m directly -- nothing to combine, no discrete log.

    So the Paillier decryption factor IS the plaintext. This preserves Helios's
    call graph exactly (helios_trustee_decrypt -> combine_decryptions ->
    result), and Trustee.decryption_factors is already typed
    arrayOf(arrayOf('core/BigInteger')), so it stores with no schema change.

    It also makes the absence of the dlog step visible and measurable rather
    than hidden in a branch -- and that absence is one of the structural
    differences the study exists to characterise.
    """
    return self.decrypt_factor(ciphertext)

  def decrypt(self, ciphertext, dec_factor=None, decode_m=False):
    """Mirrors EGSecretKey.decrypt's signature. Returns a PaillierPlaintext."""
    if dec_factor is None:
      dec_factor = self.decryption_factor(ciphertext)
    return PaillierPlaintext(dec_factor, self.public_key)

  # --- proof of correct decryption (build spec §2.8) ----------------------

  def decryption_factor_and_proof(self, ciphertext, challenge_generator=None):
    """
    Counterpart of EGSecretKey.decryption_factor_and_proof.

        1.  u = c * (1 - m*n) mod n^2          now an n-th power
        2.  d = n^-1 mod lambda                exists because gcd(n, lambda) = 1
        3.  v = u^d mod n                      the randomness, recovered
        4.  Pi_root on (u, v), Fiat-Shamir

    Step 3 works because u = v^n (mod n) and v^(nd) = v^(1+k*lambda) = v (mod n)
    by Carmichael's theorem.

    This gives a publicly verifiable proof of correct decryption WITHOUT any
    threshold machinery, and it is the concrete payoff of the single-trustee
    scope: dropping DKG is what makes it tractable. That turns a scope
    limitation into a design justification and should be recorded as such.

    HASHES THE COMMITMENT ONLY, not the statement. That is weaker than best
    practice, and it is exactly what Helios's ElGamal path does --
    decryption_factor_and_proof passes only proof.commitment to
    EG_fiatshamir_challenge_generator. Matching it keeps the two arms symmetric
    in both cost and security posture; deviating would introduce an asymmetry
    the thesis would then have to explain.
    """
    if challenge_generator is None:
      challenge_generator = paillier_fiatshamir_challenge_generator

    pk = self.public_key
    n, n2 = pk.n, pk.n2

    m = self.decryption_factor(ciphertext)
    c = ciphertext.c if hasattr(ciphertext, 'c') else ciphertext

    u = (c * (1 - m * n)) % n2
    d = number.inverse(n, self.lambda_)

    # Both remaining exponentiations are CRT-accelerable, and both are run
    # exclusively by the trustee. See the note on crt_pow_n / crt_pow_n2.
    #
    # use_crt_for_proofs is the ablation switch: turning it off measures what
    # CRT is worth on the proof, which is what lets the manuscript report the
    # figure rather than assert it.
    if self.use_crt_for_proofs:
      v = self.crt_pow_n(u, d)                    # was pow(u, d, n)
      proof = PaillierZKProof.generate(u, v, pk, challenge_generator,
                                       accelerator=self)
    else:
      v = pow(u, d, n)
      proof = PaillierZKProof.generate(u, v, pk, challenge_generator)

    return m, proof

  def prove_decryption(self, ciphertext):
    """Mirrors EGSecretKey.prove_decryption: returns (plaintext, proof dict)."""
    m, proof = self.decryption_factor_and_proof(ciphertext)
    return m, proof.to_dict()

  # --- trustee proof of knowledge (build spec §4.4) -----------------------

  def prove_sk(self, challenge_generator):
    """
    Returns None. Paillier generates no trustee proof of knowledge of the
    secret key.

    Its analogue is a proof of knowledge of the factorization (Poupard-Stern):
    real work, no measurement payoff. The ElGamal analogue is a single Schnorr
    proof costing about one exponentiation out of thousands per election, and
    the harness already collects 30 prove_sk_time_ns samples per run, so the
    manuscript can quantify exactly what is being omitted.

    Trustee.pok is LDObjectField(type_hint='legacy/DLogProof', null=True), so
    None persists cleanly.

    Deliberately NOT an empty proof object: an empty proof is a proof that
    verifies vacuously, which is worse than an absent one.
    """
    return None

  # --- serialization ------------------------------------------------------

  def to_dict(self):
    return {
      'p': str(self.p),
      'q': str(self.q),
      'lambda_': str(self.lambda_),
      'mu': str(self.mu),
      'public_key': self.public_key.to_dict() if self.public_key else None,
    }

  toJSONDict = to_dict

  @classmethod
  def from_dict(cls, d):
    if not d:
      return None
    sk = cls(
      p=int(d['p']),
      q=int(d['q']),
      lambda_=int(d['lambda_']),
      mu=int(d['mu']),
      public_key=(PaillierPublicKey.from_dict(d['public_key'])
                  if d.get('public_key') else None),
    )
    return sk

  fromJSONDict = from_dict


class PaillierPlaintext:
  """
  Counterpart of algs.EGPlaintext.

  m is the integer ITSELF -- there is no g^m encoding. ElGamal's
  generate_plaintexts builds g^0, g^1, ... because ElGamal.encrypt refuses to
  encrypt zero ("Can't encrypt 0 with El Gamal"). Paillier encrypts zero
  natively, which is why generate_plaintexts has to become scheme-aware.
  """

  def __init__(self, m=None, pk=None):
    self.m = m
    self.pk = pk

  def to_dict(self):
    return {'m': str(self.m)}

  @classmethod
  def from_dict(cls, d):
    return cls(m=int(d['m']))

  def __eq__(self, other):
    return other is not None and self.m == other.m


class PaillierCiphertext:
  """Counterpart of algs.EGCiphertext / elgamal.Ciphertext."""

  datatype = 'paillier/Ciphertext'

  def __init__(self, c=None, pk=None):
    self.c = c
    self.pk = pk

  def __mul__(self, other):
    """
    Homomorphic addition:  Enc(m1) * Enc(m2) mod n^2 = Enc(m1 + m2).

    The 0 and 1 identity cases mirror EGCiphertext.__mul__ exactly, and are the
    reason homomorphic_sum can still be initialised to 0 in homomorphic.py
    without a scheme branch.
    """
    if isinstance(other, int) and (other == 0 or other == 1):
      return self

    if self.pk != other.pk:
      raise Exception('different PKs!')

    return PaillierCiphertext((self.c * other.c) % self.pk.n2, self.pk)

  def __eq__(self, other):
    if other is None:
      return False
    return self.c == other.c

  # --- ballot validity proofs (build spec §2.6, §2.7) ---------------------

  def _statement_for(self, plaintext):
    """
    The Pi_root statement for "this ciphertext encrypts m_j":

        u_j = c * (1+n)^(-m_j) mod n^2  =  c * (1 - m_j*n) mod n^2

    ONE MULTIPLICATION, never an exponentiation, because
    (1 + j*n)(1 - j*n) = 1 - j^2 n^2 = 1 (mod n^2), so (1+n)^(-j) = 1 - j*n.

    Exactly one u_j over the candidate plaintexts is an n-th power -- the one
    matching the encrypted message -- with the encryption randomness as witness,
    since Enc(m, v) * (1+n)^(-m) = v^n. That equivalence is why Pi_root is the
    right base protocol: proving c encrypts m_j IS proving c*(1 - m_j n) is an
    n-th power.
    """
    n, n2 = self.pk.n, self.pk.n2
    m = plaintext.m if hasattr(plaintext, 'm') else plaintext
    return (self.c * (1 - m * n)) % n2

  def generate_encryption_proof(self, plaintext, randomness, challenge_generator):
    # The stored randomness is the Pi_root witness under the standard scheme,
    # and an exponent under DJN §4.1 -- pk.proof_witness resolves the two.
    # Everything downstream of this line is identical in both modes.
    return PaillierZKProof.generate(
      self._statement_for(plaintext), self.pk.proof_witness(randomness),
      self.pk, challenge_generator)

  def simulate_encryption_proof(self, plaintext, challenge=None):
    return PaillierZKProof.simulate(
      self._statement_for(plaintext), self.pk, challenge)

  def generate_disjunctive_encryption_proof(self, plaintexts, real_index,
                                            randomness, challenge_generator):
    """
    CDS 1-out-of-L composition over L instances of Pi_root.

    This mirrors EGCiphertext.generate_disjunctive_encryption_proof step for
    step, including the real_challenge_generator closure that plants the real
    commitment, hashes all commitments, then subtracts the simulated challenges.
    Keeping that structure is what lets the call sites in homomorphic.py stay
    scheme-agnostic. The only substantive difference is that Helios reduces the
    real challenge % pk.q and this reduces % 2^160.

    Cite Cramer-Damgard-Schoenmakers 1994 for the general L-way form, not DJN,
    which gives 1-out-of-2 only. Q1 of the 2025 NLE face needs L = 13.

    The proof list is built BY INDEX, never by appending, so the real branch's
    position is not inferable from anything but the (indistinguishable) values.
    """
    proofs = [None for _ in plaintexts]

    # go through all plaintexts and simulate the ones that must be simulated.
    for p_num in range(len(plaintexts)):
      if p_num != real_index:
        proofs[p_num] = self.simulate_encryption_proof(plaintexts[p_num])

    # the function that generates the challenge
    def real_challenge_generator(commitment):
      # set up the partial real proof so we're ready to get the hash
      proofs[real_index] = PaillierZKProof()
      proofs[real_index].commitment = commitment

      # get the commitments in a list and generate the whole disjunctive challenge
      commitments = [p.commitment for p in proofs]
      disjunctive_challenge = challenge_generator(commitments)

      # now we must subtract all of the other challenges from this challenge.
      real_challenge = disjunctive_challenge
      for p_num in range(len(proofs)):
        if p_num != real_index:
          real_challenge = real_challenge - proofs[p_num].challenge

      # mod 2^160, the challenge modulus (ElGamal reduces mod q here)
      return real_challenge % CHALLENGE_MODULUS

    real_proof = self.generate_encryption_proof(
      plaintexts[real_index], randomness, real_challenge_generator)

    proofs[real_index] = real_proof

    return PaillierZKDisjunctiveProof(proofs)

  def verify_encryption_proof(self, plaintext, proof):
    return proof.verify(self._statement_for(plaintext), self.pk)

  def verify_disjunctive_encryption_proof(self, plaintexts, proof,
                                          challenge_generator):
    """
    Every branch verifies, AND the branch challenges sum to the hash of all
    commitments. The second half is what makes it 1-out-of-L: without it a
    prover could simulate every branch independently.
    """
    if len(plaintexts) != len(proof.proofs):
      return False

    for i in range(len(plaintexts)):
      if not self.verify_encryption_proof(plaintexts[i], proof.proofs[i]):
        return False

    return (challenge_generator([p.commitment for p in proof.proofs]) ==
            (sum([p.challenge for p in proof.proofs]) % CHALLENGE_MODULUS))

  def decrypt(self, decryption_factors, public_key):
    """
    Single trustee (build spec §4.6, enforcement point 4).

    combine_decryptions (models.py:519-528) always passes a LIST of per-trustee
    factor sets. Returning decryption_factors[0] silently would produce a
    plausible-looking but wrong result if a second trustee ever existed -- which
    is exactly the failure mode that reaches a results chapter unnoticed. So it
    asserts instead.
    """
    if len(decryption_factors) != 1:
      raise NotImplementedError(
        "Paillier elections support exactly one trustee, got %s decryption "
        "factor sets; threshold Paillier requires DKG, which is out of scope. "
        "See PAILLIER_BUILD_SPEC.md §4.6." % len(decryption_factors))

    return int(decryption_factors[0])

  def check_group_membership(self, pk):
    """A ciphertext must be a unit mod n^2."""
    if not (0 < self.c < pk.n2):
      return False
    return math.gcd(self.c, pk.n) == 1

  def to_dict(self):
    return {'c': str(self.c)}

  toJSONDict = to_dict

  def to_string(self):
    return "%s" % self.c

  @classmethod
  def from_dict(cls, d, pk=None):
    return cls(c=int(d['c']), pk=pk)

  fromJSONDict = from_dict

  @classmethod
  def from_string(cls, s):
    return cls.from_dict({'c': s})


# ---------------------------------------------------------------------------
# Pi_root — proof of knowledge of an n-th root (build spec §2.5)
# ---------------------------------------------------------------------------

class PaillierZKProof:
  """
  Counterpart of algs.EGZKProof. DJN §5.2 at s = 1, the Paillier analogue of
  Chaum-Pedersen.

      Statement:  u in Z*_{n^2} is an n-th power: exists v in Z*_n, u = v^n mod n^2
      Witness:    v

      Prove:      r <-$ Z*_n
                  a = r^n mod n^2
                  e = challenge_generator(a)          in [0, 2^160)
                  z = r * v^e mod n                   <- MOD n. NOT mod n^2.

      Verify:     z^n = a * u^e  (mod n^2)
                  and gcd(z,n) = gcd(u,n) = gcd(a,n) = 1

  `commitment` is a SCALAR, where EGZKProof's is {'A': ..., 'B': ...}. That is a
  deliberate shape difference and the reason Paillier's proof layer is relatively
  cheaper than its ciphertext arithmetic alone would suggest: Chaum-Pedersen must
  compute A = g^w and B = y^w and its simulator must solve for both, while
  Pi_root computes one value and solves for one. The field NAME is kept so the
  harness's proof_bytes slicing is unaffected.
  """

  datatype = 'paillier/ZKProof'

  def __init__(self, commitment=None, challenge=None, response=None):
    self.commitment = commitment
    self.challenge = challenge
    self.response = response

  @classmethod
  def generate(cls, u, v, pk, challenge_generator, accelerator=None):
    """
    Honest proof that `u` is an n-th power with witness `v`.

    THE REDUCTION MODULUS IN THE RESPONSE IS NOT COSMETIC. `z` is reduced mod n,
    never mod n^2. Reducing mod n^2 still verifies -- z^n mod n^2 depends only on
    z mod n^2 -- while making the honest branch's z about twice the bit length of
    every simulated branch's. The real branch then becomes identifiable by
    inspection and ballot secrecy is gone.

    This is exactly the bug in ishaq/Paillier-E-Voting. It is invisible to
    functional testing: every proof still verifies. Test 11 compares the bit-
    length distributions of real and simulated responses and exists solely to
    catch it.
    """
    n, n2 = pk.n, pk.n2

    r = random_z_star_n(n)

    # `accelerator` is a secret key, passed ONLY when the prover happens to
    # hold the factorization -- i.e. the trustee proving correct decryption.
    # The voter never has one, so ballot proofs are unaffected and remain
    # exactly as costly as before. Same transcript either way; only the route
    # to a differs.
    if accelerator is not None:
      a = accelerator.crt_pow_n2(r, n)
    else:
      a = pow(r, n, n2)

    e = challenge_generator(a)
    z = (r * pow(v, e, n)) % n          # mod n -- see docstring

    return cls(commitment=a, challenge=e, response=z)

  @classmethod
  def simulate(cls, u, pk, challenge=None):
    """
    Simulated transcript for a false branch.

        given e:  z <-$ Z*_n
                  a = z^n * (u^e)^-1 mod n^2

    Satisfies the verification equation by construction, and is distributed
    identically to an honest transcript -- which is what makes the disjunctive
    proof witness-indistinguishable.
    """
    n, n2 = pk.n, pk.n2

    if challenge is None:
      challenge = random_lt(CHALLENGE_MODULUS)

    z = random_z_star_n(n)
    a = (pow(z, n, n2) * number.inverse(pow(u, challenge, n2), n2)) % n2

    return cls(commitment=a, challenge=challenge, response=z)

  def verify(self, u, pk, challenge_generator=None):
    """z^n == a * u^e (mod n^2), plus unit checks on z, u and a."""
    n, n2 = pk.n, pk.n2

    if self.commitment is None or self.challenge is None or self.response is None:
      return False

    # Unit checks. Without them a malicious prover could submit a value sharing
    # a factor with n, for which the exponentiation identities do not hold.
    for value in (self.response, u, self.commitment):
      if value % n == 0 or math.gcd(value, n) != 1:
        return False

    left = pow(self.response, n, n2)
    right = (self.commitment * pow(u, self.challenge, n2)) % n2

    if left != right:
      return False

    if challenge_generator is not None:
      if self.challenge != challenge_generator(self.commitment):
        return False

    return True

  def to_dict(self):
    return {
      'commitment': str(self.commitment),
      'challenge': str(self.challenge),
      'response': str(self.response),
    }

  toJSONDict = to_dict

  @classmethod
  def from_dict(cls, d):
    return cls(commitment=int(d['commitment']),
               challenge=int(d['challenge']),
               response=int(d['response']))

  fromJSONDict = from_dict


class PaillierZKDisjunctiveProof:
  """Counterpart of algs.EGZKDisjunctiveProof. Serializes as a BARE ARRAY."""

  datatype = 'paillier/ZKDisjunctiveProof'

  def __init__(self, proofs=None):
    self.proofs = proofs

  def to_dict(self):
    return [p.to_dict() for p in self.proofs]

  toJSONDict = to_dict

  @classmethod
  def from_dict(cls, d):
    return cls(proofs=[PaillierZKProof.from_dict(p) for p in d])

  fromJSONDict = from_dict


def extract_witness(u, pk, transcript_a, e1, z1, e2, z2):
  """
  Special-soundness extraction (build spec §2.5, test 10).

  From two accepting transcripts (a, e1, z1) and (a, e2, z2) with e1 != e2:

      d = e1 - e2
      since 0 < |d| < 2^160 < min(p, q), gcd(d, n) = 1, so extended-gcd gives
      alpha, beta with alpha*d + beta*n = 1, and

      v = (z1 * z2^-1)^alpha * u^beta  mod n

  satisfies v^n = u (mod n^2), because
  ((z1/z2)^alpha u^beta)^n = (u^d)^alpha u^(beta n) = u^(alpha d + beta n) = u.

  This is what makes the proof a proof of KNOWLEDGE rather than merely a
  convincing transcript, and the reason t = 160 is sound at 1024-bit primes:
  extraction needs 2^t below the smallest prime factor of n, leaving ~864 bits
  of margin.
  """
  n = pk.n
  d = e1 - e2
  if d == 0:
    raise ValueError("challenges must differ to extract a witness")

  # alpha*d + beta*n = gcd(d, n) = 1
  g, alpha, beta = _extended_gcd(d, n)
  if g != 1:
    raise ValueError("gcd(e1 - e2, n) != 1; extraction impossible")

  ratio = (z1 * number.inverse(z2, n)) % n
  return (pow(ratio, alpha, n) * pow(u % n, beta, n)) % n


def _extended_gcd(a, b):
  """Returns (g, x, y) with a*x + b*y = g = gcd(a, b)."""
  old_r, r = a, b
  old_s, s = 1, 0
  old_t, t = 0, 1
  while r != 0:
    q = old_r // r
    old_r, r = r, old_r - q * r
    old_s, s = s, old_s - q * s
    old_t, t = t, old_t - q * t
  if old_r < 0:
    old_r, old_s, old_t = -old_r, -old_s, -old_t
  return old_r, old_s, old_t
