"""
Correctness suite for the Paillier-Helios arm (build spec §7).

Tests 1-4 are the manuscript's; 5-16 are additions. Small keys everywhere except
where a test is explicitly marked full-size, so the suite runs in seconds.

Test 15 (the ElGamal golden ballot) lives here rather than in tests.py because it
exists to guard the Paillier work: it is the only thing that proves the §4.2
scheme-agnostic refactor left the ElGamal path byte-identical. Its baseline is
captured at B0, BEFORE any change, and cannot be reconstructed afterwards.
"""

import contextlib
import datetime
import json
import math
import os
import random as _stdlib_random
import statistics
import unittest

from django.test import TestCase

from helios import datatypes, utils
from helios.crypto import utils as cryptoutils

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')


# ---------------------------------------------------------------------------
# Deterministic randomness
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def seeded_randomness(seed):
  """
  Make Helios's crypto randomness reproducible for the duration of the block.

  helios.crypto.utils exposes a module-level StrongRandom instance, and
  random_mpz_lt binds it as a default argument at definition time. So every
  consumer -- algs.py, elgamal.py and anything mirroring them -- ultimately
  calls getrandbits() on that one object. Swapping that single method is
  therefore sufficient, and is what lets a golden ballot exist at all.

  Note this seeds a stdlib Mersenne Twister. That is correct HERE and nowhere
  else: the point is reproducibility of a test vector, not unpredictability.
  """
  rng = _stdlib_random.Random(seed)
  original = cryptoutils.random.getrandbits
  cryptoutils.random.getrandbits = rng.getrandbits
  try:
    yield
  finally:
    cryptoutils.random.getrandbits = original


class _FakeElection:
  """The two attributes EncryptedAnswer.fromElectionAndAnswer actually reads."""

  def __init__(self, questions, public_key):
    self.questions = questions
    self.public_key = public_key


# The golden ballot face. One question, four answers, min 0 max 2 -- so the
# overall proof has L = 3 branches. Two branches would let a 1-out-of-2 bug pass
# unnoticed as a 1-out-of-L bug; three is the smallest face that distinguishes
# them while staying fast.
GOLDEN_QUESTIONS = [{
  'answer_urls': [None, None, None, None],
  'answers': ['Alice', 'Bob', 'Carol', 'Dave'],
  'choice_type': 'approval',
  'max': 2,
  'min': 0,
  'question': 'Golden ballot question',
  'result_type': 'absolute',
  'short_name': 'Golden',
  'tally_type': 'homomorphic',
}]

GOLDEN_SEED = 20260906
GOLDEN_ANSWER = [0, 2]
GOLDEN_PATH = os.path.join(FIXTURE_DIR, 'elgamal_golden_ballot.json')


def build_golden_elgamal_ballot():
  """
  Deterministically produce one ElGamal EncryptedAnswer, serialized.

  Everything random is drawn from GOLDEN_SEED: the trustee keypair, the
  encryption randomness, every proof commitment and every simulated branch. Run
  twice on the same code, this returns identical bytes; run across a change that
  perturbs the ElGamal path in any way, it does not.
  """
  from helios.views import ELGAMAL_PARAMS
  from helios.workflows.homomorphic import EncryptedAnswer

  with seeded_randomness(GOLDEN_SEED):
    keypair = ELGAMAL_PARAMS.generate_keypair()
    election = _FakeElection(GOLDEN_QUESTIONS, keypair.pk)
    answer = EncryptedAnswer.fromElectionAndAnswer(election, 0, GOLDEN_ANSWER)

    # Serialized through the datatypes layer, not pk.toJSONDict(): ELGAMAL_PARAMS
    # is an elgamal.Cryptosystem, so keypair.pk is an elgamal.PublicKey, which
    # carries no toJSONDict -- only algs.EGPublicKey does. That is the two-lineage
    # split described in build spec §1.2, met here in its mildest form.
    ld = datatypes.LDObject.instantiate(answer, datatype='legacy/EncryptedAnswer')
    pk_ld = datatypes.LDObject.instantiate(keypair.pk, datatype='legacy/EGPublicKey')
    return {
      'public_key': pk_ld.toDict(),
      'encrypted_answer': ld.toDict(),
    }


class ElGamalGoldenBallotTests(unittest.TestCase):
  """
  Test 15 -- the additive-only enforcement gate (masterplan §3.4).

  The manuscript claims "No modifications are made to ElGamal-Helios" (§9.2.1).
  The upstream suite passing is necessary but not sufficient for that: a refactor
  can preserve every assertion while changing the bytes on the wire -- a
  different operation order, a challenge computed over a differently formatted
  string, randomness drawn in a different sequence. Any of those would silently
  invalidate comparability against the already-collected ElGamal measurements.

  This test compares bytes.
  """

  def test_15_golden_ballot_is_byte_identical(self):
    if not os.path.exists(GOLDEN_PATH):
      self.skipTest(
        f'no baseline at {GOLDEN_PATH} — capture it with '
        f'`python -m helios.capture_golden_ballot` on an unmodified tree')

    with open(GOLDEN_PATH) as f:
      expected = f.read()

    actual = utils.to_json(build_golden_elgamal_ballot())

    self.assertEqual(
      expected, actual,
      'The ElGamal ballot serialization changed. This is the guard on '
      '"no modifications are made to ElGamal-Helios" — either the change to '
      'the ElGamal path was unintentional and must be reverted, or it was '
      'deliberate and the manuscript claim no longer holds. Do not regenerate '
      'this fixture to make the test pass.')

  def test_15b_golden_ballot_generation_is_deterministic(self):
    """
    Guards the guard. If the generator were not itself reproducible, test 15
    would fail for reasons unrelated to the ElGamal path and would be
    disabled -- which is how a regression gate quietly stops gating.
    """
    self.assertEqual(utils.to_json(build_golden_elgamal_ballot()),
                     utils.to_json(build_golden_elgamal_ballot()))


# ---------------------------------------------------------------------------
# Shared key material
# ---------------------------------------------------------------------------
#
# Small primes everywhere except where a test is explicitly full-size, so the
# suite runs in seconds. These are the sizes phe's own unit tests use, which
# makes them checkable by hand and gives deterministic seeds for the oracle
# comparison in test 14.

TOY_P, TOY_Q = 1019, 1031            # n = 1_050_589
MEDIUM_P, MEDIUM_Q = 1000003, 1000033  # n ~ 10^12, room for large tallies


def toy_keypair():
  from helios.crypto.paillier import PaillierKeyPair
  return PaillierKeyPair.from_primes(TOY_P, TOY_Q)


def medium_keypair():
  from helios.crypto.paillier import PaillierKeyPair
  return PaillierKeyPair.from_primes(MEDIUM_P, MEDIUM_Q)


class PaillierCoreTests(unittest.TestCase):
  """Milestone B2 — keygen, encryption, decryption, CRT, homomorphic addition."""

  def setUp(self):
    from helios.crypto import paillier
    self.paillier = paillier
    self.kp = medium_keypair()
    self.pk, self.sk = self.kp.pk, self.kp.sk

  def _pt(self, m):
    return self.paillier.PaillierPlaintext(m, self.pk)

  # --- test 1 -------------------------------------------------------------

  def test_01_decryption_correctness_both_paths(self):
    """
    Dec(Enc(m)) == m on BOTH the CRT and non-CRT paths.

    Edge values matter more than the middle here: 0 is the value ElGamal cannot
    encrypt at all and the one that exposed the core/BigInteger bug (§1.3), and
    n-1 is the largest representable plaintext.
    """
    n = self.pk.n
    for m in (0, 1, 2, 10, 12, 10 ** 6, n - 2, n - 1):
      c = self.pk.encrypt(self._pt(m))
      self.assertEqual(self.sk.decryption_factor(c), m, f'CRT path, m={m}')
      self.assertEqual(self.sk.decrypt_no_crt(c), m, f'non-CRT path, m={m}')

  def test_01b_encryption_is_randomized(self):
    """Two encryptions of the same message must differ, or secrecy is gone."""
    a = self.pk.encrypt(self._pt(1))
    b = self.pk.encrypt(self._pt(1))
    self.assertNotEqual(a.c, b.c)
    self.assertEqual(self.sk.decryption_factor(a),
                     self.sk.decryption_factor(b))

  def test_01c_encrypt_with_r_is_deterministic_given_r(self):
    """The proofs depend on r being the witness for exactly this ciphertext."""
    r = 424242
    a = self.pk.encrypt_with_r(self._pt(3), r)
    b = self.pk.encrypt_with_r(self._pt(3), r)
    self.assertEqual(a.c, b.c)

  def test_01d_encode_message_is_refused_not_ignored(self):
    """
    Signature parity with EGPublicKey.encrypt_with_r, but silently ignoring the
    flag would let a caller believe subgroup encoding happened.
    """
    with self.assertRaises(Exception):
      self.pk.encrypt_with_r(self._pt(1), 5, encode_message=True)

  # --- test 2 -------------------------------------------------------------

  def test_02_homomorphic_addition(self):
    """Dec(Enc(m1) * Enc(m2) mod n^2) == m1 + m2."""
    for m1, m2 in ((0, 0), (0, 1), (1, 1), (7, 5), (123456, 654321)):
      c1 = self.pk.encrypt(self._pt(m1))
      c2 = self.pk.encrypt(self._pt(m2))
      self.assertEqual(self.sk.decryption_factor(c1 * c2), m1 + m2)

  def test_02b_multiplication_identities_match_elgamal(self):
    """
    homomorphic.py initialises homomorphic_sum to the int 0 and relies on
    EGCiphertext.__mul__ returning self for 0 and 1. PaillierCiphertext must do
    the same, or that line needs a scheme branch it should not need.
    """
    c = self.pk.encrypt(self._pt(4))
    self.assertIs(c * 0, c)
    self.assertIs(c * 1, c)

  def test_02c_addition_accumulates_over_many_terms(self):
    """The tally path multiplies N ciphertexts into one running product."""
    running = 0
    total = 0
    for m in range(20):
      running = self.pk.encrypt(self._pt(m)) * running
      total += m
    self.assertEqual(self.sk.decryption_factor(running), total)

  # --- test 3 -------------------------------------------------------------

  def test_03_end_to_end_tally(self):
    """
    Per-slot tally equals the plaintext sum, over a smoke ballot face.

    This is the homomorphic property in the shape Helios actually uses it:
    one ciphertext per candidate per ballot, multiplied down each column.
    """
    votes = [
      [1, 0, 0],
      [1, 0, 0],
      [0, 1, 0],
      [0, 0, 1],
      [1, 0, 0],
    ]
    expected = [3, 1, 1]

    tally = [0, 0, 0]
    for ballot in votes:
      for slot, bit in enumerate(ballot):
        tally[slot] = self.pk.encrypt(self._pt(bit)) * tally[slot]

    self.assertEqual([self.sk.decryption_factor(t) for t in tally], expected)

  def test_03b_zero_tally_decrypts_to_zero(self):
    """
    A candidate nobody voted for. This is the case that made the §1.3
    core/BigInteger bug fatal rather than cosmetic.
    """
    tally = 0
    for _ in range(5):
      tally = self.pk.encrypt(self._pt(0)) * tally
    self.assertEqual(self.sk.decryption_factor(tally), 0)

  # --- test 4 -------------------------------------------------------------

  def test_04_schema_conformance(self):
    """
    Every datatype round-trips through LDObject unchanged, decimal strings only.
    """
    kp = toy_keypair()

    pk_ld = datatypes.LDObject.instantiate(kp.pk, datatype='paillier/PublicKey')
    pk_dict = pk_ld.toDict()
    self.assertEqual(pk_dict, {'n': str(kp.pk.n), 'g': str(kp.pk.g)})
    self.assertTrue(all(isinstance(v, str) for v in pk_dict.values()))

    back = datatypes.LDObject.fromDict(pk_dict, type_hint='paillier/PublicKey')
    self.assertEqual(back.wrapped_obj.n, kp.pk.n)
    self.assertEqual(back.wrapped_obj.g, kp.pk.g)

    ct = kp.pk.encrypt(self.paillier.PaillierPlaintext(1, kp.pk))
    ct_ld = datatypes.LDObject.instantiate(ct, datatype='paillier/Ciphertext')
    ct_dict = ct_ld.toDict()
    self.assertEqual(set(ct_dict), {'c'})
    self.assertEqual(ct_dict['c'], str(ct.c))

    ct_back = datatypes.LDObject.fromDict(ct_dict,
                                          type_hint='paillier/Ciphertext')
    self.assertEqual(ct_back.wrapped_obj.c, ct.c)

    sk_ld = datatypes.LDObject.instantiate(kp.sk, datatype='paillier/SecretKey')
    sk_dict = sk_ld.toDict()
    self.assertEqual(set(sk_dict), {'public_key', 'p', 'q', 'lambda_', 'mu'})
    self.assertEqual(sk_dict['p'], str(kp.sk.p))

  def test_04b_ciphertext_routes_through_the_elgamal_type_hint(self):
    """
    The B0 dispatch, now with a real Paillier object: a ciphertext stored under
    the static 'legacy/EGCiphertext' hint that CastVote.vote resolves to must
    come back as Paillier, not be handed to the ElGamal deserializer.
    """
    kp = toy_keypair()
    ct = kp.pk.encrypt(self.paillier.PaillierPlaintext(1, kp.pk))

    serialized = datatypes.LDObject.instantiate(
      ct, datatype='legacy/EGCiphertext').toDict()
    self.assertEqual(set(serialized), {'c'})

    back = datatypes.LDObject.fromDict(serialized,
                                       type_hint='legacy/EGCiphertext')
    self.assertIsInstance(back.wrapped_obj, self.paillier.PaillierCiphertext)
    self.assertEqual(back.wrapped_obj.c, ct.c)

  def test_04c_public_key_routes_through_the_elgamal_type_hint(self):
    kp = toy_keypair()
    serialized = datatypes.LDObject.instantiate(
      kp.pk, datatype='legacy/EGPublicKey').toDict()
    self.assertEqual(set(serialized), {'n', 'g'})

    back = datatypes.LDObject.fromDict(serialized,
                                       type_hint='legacy/EGPublicKey')
    self.assertIsInstance(back.wrapped_obj, self.paillier.PaillierPublicKey)

  # --- test 13 ------------------------------------------------------------

  def test_13_crt_agreement(self):
    """Both decryption paths agree on the same ciphertexts."""
    for m in (0, 1, 2, 999, 10 ** 6):
      c = self.pk.encrypt(self._pt(m))
      self.assertEqual(self.sk.decryption_factor(c), self.sk.decrypt_no_crt(c))

  def test_13b_h_p_closed_form_matches_the_long_way(self):
    """
    A free check that the derivation and the code agree.

    The closed form h_p = (-q)^-1 mod p follows because
    (1+pq)^(p-1) = 1 + (p-1)pq (mod p^2) -- every higher binomial term carries
    (pq)^2, which vanishes mod p^2. DJN gives one sentence about CRT and no
    algorithm, so this step is derived rather than quoted, and worth checking.
    """
    from Crypto.Util import number

    for kp in (toy_keypair(), medium_keypair()):
      p, q, g = kp.sk.p, kp.sk.q, kp.pk.g

      long_way_p = number.inverse((pow(g, p - 1, p * p) - 1) // p, p)
      long_way_q = number.inverse((pow(g, q - 1, q * q) - 1) // q, q)

      self.assertEqual(kp.sk.h_p, long_way_p, 'h_p closed form disagrees')
      self.assertEqual(kp.sk.h_q, long_way_q, 'h_q closed form disagrees')

  def test_13d_crt_exponentiation_helpers_agree_with_pow(self):
    """
    crt_pow_n and crt_pow_n2 accelerate the DECRYPTION PROOF, which is separate
    from decryption itself. A wrong CRT recombination here would produce a
    proof that simply fails to verify -- loud -- but a wrong exponent REDUCTION
    would produce a plausible number that is silently wrong, so both are
    checked against pow() directly.

    crt_pow_n2 reduces the exponent mod lambda(p^2) = p(p-1), not mod (p-1).
    Z*_{p^2} has order p(p-1); using the smaller modulus is the natural mistake
    and gives a wrong answer that still looks like a group element.
    """
    from helios.crypto import paillier as P

    kp = P.Paillier(key_size=512).generate_keypair()
    pk, sk = kp.pk, kp.sk

    for _ in range(8):
      base = P.random_z_star_n(pk.n)
      exponent = P.random_lt(pk.n)

      self.assertEqual(sk.crt_pow_n(base, exponent),
                       pow(base, exponent, pk.n))
      self.assertEqual(sk.crt_pow_n2(base, exponent),
                       pow(base, exponent, pk.n2))

    # the two exponents the decryption proof actually uses
    from Crypto.Util import number
    d = number.inverse(pk.n, sk.lambda_)
    u = P.random_z_star_n(pk.n)
    self.assertEqual(sk.crt_pow_n(u, d), pow(u, d, pk.n))
    self.assertEqual(sk.crt_pow_n2(u, pk.n), pow(u, pk.n, pk.n2))

  def test_13e_decryption_proof_identical_with_and_without_crt(self):
    """
    CRT is an acceleration, not a different protocol: both paths must produce
    proofs that verify, and both must reject a wrong plaintext. The transcripts
    differ only in their randomness.
    """
    from helios.crypto import paillier as P

    kp = P.Paillier(key_size=512).generate_keypair()
    pk, sk = kp.pk, kp.sk
    ct = pk.encrypt(P.PaillierPlaintext(4242, pk))

    try:
      for use_crt in (False, True):
        sk.use_crt_for_proofs = use_crt

        m, proof = sk.decryption_factor_and_proof(ct)
        self.assertEqual(m, 4242, f'use_crt_for_proofs={use_crt}')
        self.assertTrue(pk.verify_decryption_proof(ct, m, proof),
                        f'use_crt_for_proofs={use_crt}')
        self.assertFalse(pk.verify_decryption_proof(ct, m + 1, proof),
                         f'use_crt_for_proofs={use_crt}')
    finally:
      sk.use_crt_for_proofs = True

  def test_13f_ballot_proofs_never_use_the_accelerator(self):
    """
    The accelerator is a secret key. A voter has none, so ballot proofs must be
    unaffected -- if a code path ever fed one in, the browser would be trying
    to use a factorization it does not have.
    """
    from helios.crypto import paillier as P
    import inspect

    source = inspect.getsource(P.PaillierCiphertext.generate_encryption_proof)
    self.assertNotIn('accelerator', source,
                     'ballot proofs must not pass an accelerator')

    # and the default really is None
    sig = inspect.signature(P.PaillierZKProof.generate)
    self.assertIsNone(sig.parameters['accelerator'].default)

  def test_13c_mu_closed_form_matches_the_general_definition(self):
    """
    mu = lambda^-1 mod n is a simplification of (L(g^lambda mod n^2))^-1 mod n,
    valid only because g = 1+n. Derived in the masterplan; checked here.
    """
    from Crypto.Util import number

    for kp in (toy_keypair(), medium_keypair()):
      n, n2, g, lam = kp.pk.n, kp.pk.n2, kp.pk.g, kp.sk.lambda_
      general = number.inverse((pow(g, lam, n2) - 1) // n, n)
      self.assertEqual(kp.sk.mu, general)

  # --- test 14 ------------------------------------------------------------

  def test_14_oracle_agreement_with_phe(self):
    """
    Fixed (p, q, m, v) must produce byte-identical ciphertexts and plaintexts
    against data61/python-paillier.

    phe is GPLv3 and this tree is Apache-2.0: it is an EXTERNAL ORACLE ONLY.
    Nothing under helios/ imports it and no line of it is copied. It is the
    right oracle because it matches this scheme exactly -- g = n+1, CRT over
    p^2/q^2 -- so a disagreement is a real disagreement rather than a
    difference of convention.
    """
    try:
      from phe import paillier as phe
    except ImportError:
      self.skipTest('phe not installed (test-only dependency)')

    for p, q in ((TOY_P, TOY_Q), (MEDIUM_P, MEDIUM_Q)):
      kp = self.paillier.PaillierKeyPair.from_primes(p, q)
      phe_pub = phe.PaillierPublicKey(p * q)
      phe_priv = phe.PaillierPrivateKey(phe_pub, p, q)

      self.assertEqual(kp.pk.g, phe_pub.g, 'g convention differs')

      for m, v in ((0, 7), (1, 11), (2, 13), (12, 1234), (99999, 65537)):
        ours = kp.pk.encrypt_with_r(
          self.paillier.PaillierPlaintext(m, kp.pk), v).c
        theirs = phe_pub.raw_encrypt(m, r_value=v)

        self.assertEqual(ours, theirs,
                         f'ciphertext differs at p={p} m={m} v={v}')
        self.assertEqual(phe_priv.raw_decrypt(ours), m)
        self.assertEqual(kp.sk.decryption_factor(theirs), m,
                         'our CRT decryption disagrees with phe ciphertext')


def _two_sample_ks(a, b):
  """
  Two-sample Kolmogorov-Smirnov statistic and its 1% critical value.

  Implemented here rather than pulled from scipy: scipy is not a dependency of
  this project and adding one for a single statistic in a single test is not a
  trade worth making.

      D = max |F_a(x) - F_b(x)|
      D_crit(alpha) = c(alpha) * sqrt((n+m) / (n*m)),  c(0.01) = 1.628
  """
  a, b = sorted(a), sorted(b)
  n, m = len(a), len(b)

  values = sorted(set(a) | set(b))
  d = 0.0
  i = j = 0
  for x in values:
    while i < n and a[i] <= x:
      i += 1
    while j < m and b[j] <= x:
      j += 1
    d = max(d, abs(i / n - j / m))

  d_crit = 1.628 * math.sqrt((n + m) / (n * m))
  return d, d_crit


class PaillierProofTests(unittest.TestCase):
  """
  Milestone B3 — Pi_root, the 1-out-of-L composition, and the decryption proof.

  Tests 5, 6, 8, 10 and 12 are what make the word "verifiable" in the thesis
  title honest. Test 11 is what makes "secret" honest. A Paillier-Helios that
  produces fast-but-unsound proofs would benchmark beautifully and mean nothing.
  """

  def setUp(self):
    from helios.crypto import paillier
    self.paillier = paillier
    self.gen = paillier.paillier_disjunctive_challenge_generator
    self.kp = medium_keypair()
    self.pk, self.sk = self.kp.pk, self.kp.sk
    self.bits = [paillier.PaillierPlaintext(i, self.pk) for i in (0, 1)]

  def _plaintexts(self, lo, hi):
    return [self.paillier.PaillierPlaintext(i, self.pk)
            for i in range(lo, hi + 1)]

  def _encrypt(self, m):
    return self.pk.encrypt_return_r(self.paillier.PaillierPlaintext(m, self.pk))

  # --- test 5 -------------------------------------------------------------

  def test_05_individual_proof_soundness(self):
    """
    A ciphertext of 2 must not be provable as 0-or-1.

    This is the check that stops a voter casting 2 votes for one candidate. The
    prover here is honest about its randomness and simply lies about the
    message, which is the cheapest possible attack.
    """
    c, r = self._encrypt(2)

    for claimed_index in (0, 1):
      proof = c.generate_disjunctive_encryption_proof(
        self.bits, claimed_index, r, self.gen)
      self.assertFalse(
        c.verify_disjunctive_encryption_proof(self.bits, proof, self.gen),
        f'a ciphertext of 2 verified as bit {claimed_index}')

  def test_05b_ciphertext_of_minus_one_is_rejected(self):
    """The other direction: a negative vote would subtract from a tally."""
    c, r = self._encrypt(self.pk.n - 1)   # -1 mod n
    proof = c.generate_disjunctive_encryption_proof(self.bits, 1, r, self.gen)
    self.assertFalse(
      c.verify_disjunctive_encryption_proof(self.bits, proof, self.gen))

  # --- test 6 -------------------------------------------------------------

  def test_06_overall_proof_soundness(self):
    """
    13 selections in a max-12 question must fail.

    Q1 of the 2025 NLE face is min 0, max 12, so L = 13 branches cover 0..12.
    A ballot selecting 13 candidates has a homomorphic sum outside every branch.
    """
    sum_plaintexts = self._plaintexts(0, 12)

    C, V, selected = 0, 1, 0
    for i in range(20):
      bit = 1 if i < 13 else 0
      c, r = self._encrypt(bit)
      C = c * C
      V = self.pk.combine_randomness(V, r) if hasattr(
        self.pk, 'combine_randomness') else (V * r) % self.pk.n
      selected += bit

    self.assertEqual(selected, 13)

    # There is no honest branch to point at; the closest lie is "12".
    proof = C.generate_disjunctive_encryption_proof(
      sum_plaintexts, 12, V, self.gen)
    self.assertFalse(
      C.verify_disjunctive_encryption_proof(sum_plaintexts, proof, self.gen),
      '13 selections verified against a max-12 question')

  def test_06b_valid_selection_counts_all_verify(self):
    """Completeness half of test 6: every legal count must pass."""
    sum_plaintexts = self._plaintexts(0, 12)

    for selected in (0, 1, 6, 12):
      C, V = 0, 1
      for i in range(12):
        bit = 1 if i < selected else 0
        c, r = self._encrypt(bit)
        C = c * C
        V = (V * r) % self.pk.n

      proof = C.generate_disjunctive_encryption_proof(
        sum_plaintexts, selected, V, self.gen)
      self.assertTrue(
        C.verify_disjunctive_encryption_proof(sum_plaintexts, proof, self.gen),
        f'{selected} legal selections failed to verify')

  def test_06c_combined_witness_is_the_product_of_randomness(self):
    """
    V = prod(v_i) mod n is the correct witness because (prod v_i)^n =
    prod(v_i^n) mod n^2. This is the multiplicative analogue of Helios's
    additive randomness_sum, and the one place "identical control flow" needs a
    named abstraction rather than a shared expression.
    """
    C, V = 0, 1
    for _ in range(4):
      c, r = self._encrypt(1)
      C = c * C
      V = (V * r) % self.pk.n

    # C should equal Enc(4, V) exactly.
    expected = self.pk.encrypt_with_r(
      self.paillier.PaillierPlaintext(4, self.pk), V)
    self.assertEqual(C.c, expected.c)

  # --- test 7 -------------------------------------------------------------

  def test_07_completeness(self):
    """
    Honestly generated proofs all verify, at both ballot widths.

    The spec asks for 1,000. That is 1,000 x (2 or 13) modexp at a 4096-bit
    modulus, which is minutes at full key size, so this runs at the toy key
    size where the arithmetic is identical and the cost is not.
    """
    kp = toy_keypair()
    pk = kp.pk
    P = self.paillier

    for L, count in ((2, 500), (13, 100)):
      plaintexts = [P.PaillierPlaintext(i, pk) for i in range(L)]
      for trial in range(count):
        real = trial % L
        c, r = pk.encrypt_return_r(P.PaillierPlaintext(real, pk))
        proof = c.generate_disjunctive_encryption_proof(
          plaintexts, real, r, self.gen)
        self.assertTrue(
          c.verify_disjunctive_encryption_proof(plaintexts, proof, self.gen),
          f'honest proof failed at L={L}, trial {trial}, real index {real}')

  # --- test 8 -------------------------------------------------------------

  def test_08_decryption_proof_soundness(self):
    """A decryption proof for a wrong plaintext must fail."""
    c, _ = self._encrypt(42)
    m, proof = self.sk.decryption_factor_and_proof(c)

    self.assertEqual(m, 42)
    self.assertTrue(self.pk.verify_decryption_proof(c, m, proof))

    for wrong in (0, 1, 41, 43, m + 1000):
      self.assertFalse(
        self.pk.verify_decryption_proof(c, wrong, proof),
        f'decryption proof accepted a wrong plaintext {wrong}')

  def test_08b_decryption_proof_is_bound_to_its_ciphertext(self):
    """A proof lifted onto a different ciphertext must not verify."""
    c1, _ = self._encrypt(7)
    c2, _ = self._encrypt(7)
    m1, proof1 = self.sk.decryption_factor_and_proof(c1)

    self.assertTrue(self.pk.verify_decryption_proof(c1, m1, proof1))
    self.assertFalse(self.pk.verify_decryption_proof(c2, m1, proof1))

  def test_08c_decryption_proof_on_a_zero_tally(self):
    """The zero case again — it decrypts, and it proves."""
    c, _ = self._encrypt(0)
    m, proof = self.sk.decryption_factor_and_proof(c)
    self.assertEqual(m, 0)
    self.assertTrue(self.pk.verify_decryption_proof(c, 0, proof))

  # --- test 10 ------------------------------------------------------------

  def test_10_special_soundness_extraction(self):
    """
    From two accepting transcripts on the SAME commitment with different
    challenges, the witness must be extractable -- which is what makes this a
    proof of knowledge rather than a convincing-looking transcript.
    """
    P = self.paillier
    pk, n, n2 = self.pk, self.pk.n, self.pk.n2

    v = P.random_z_star_n(n)
    u = pow(v, n, n2)

    # One commitment, two challenges. Rewinding, by construction.
    r = P.random_z_star_n(n)
    a = pow(r, n, n2)
    e1, e2 = 12345, 67890
    z1 = (r * pow(v, e1, n)) % n
    z2 = (r * pow(v, e2, n)) % n

    # Both transcripts must actually verify, or extraction proves nothing.
    for e, z in ((e1, z1), (e2, z2)):
      self.assertEqual(pow(z, n, n2), (a * pow(u, e, n2)) % n2)

    extracted = P.extract_witness(u, pk, a, e1, z1, e2, z2)

    self.assertEqual(pow(extracted, n, n2), u,
                     'extracted witness does not satisfy v^n = u (mod n^2)')
    self.assertEqual(extracted, v % n)

  # --- test 11 — THE ISHAQ CANARY ----------------------------------------

  def test_11_response_distribution(self):
    """
    Real and simulated responses must be indistinguishable.

    ishaq/Paillier-E-Voting reduces the real branch's response mod n^2 while
    simulated branches produce values below n. Every proof still verifies -- the
    verification equation z^n = a*u^e (mod n^2) depends only on z mod n^2 -- so
    the bug is invisible to every functional test. But the real branch's z is
    then about twice the bit length of every simulated one, and the vote can be
    read off the ballot by inspection.

    This test is the reason `z = r * v^e mod n` says mod n.
    """
    P = self.paillier
    kp = toy_keypair()
    pk = kp.pk
    plaintexts = [P.PaillierPlaintext(i, pk) for i in (0, 1)]

    real_bits, sim_bits = [], []

    for trial in range(600):
      real_index = trial % 2
      c, r = pk.encrypt_return_r(P.PaillierPlaintext(real_index, pk))
      proof = c.generate_disjunctive_encryption_proof(
        plaintexts, real_index, r, self.gen)

      for idx, p in enumerate(proof.proofs):
        (real_bits if idx == real_index else sim_bits).append(
          p.response.bit_length())

    self.assertGreater(len(real_bits), 500)
    self.assertGreater(len(sim_bits), 500)

    mean_real = statistics.mean(real_bits)
    mean_sim = statistics.mean(sim_bits)

    self.assertLess(
      abs(mean_real - mean_sim), 1.0,
      f'real responses average {mean_real:.2f} bits and simulated '
      f'{mean_sim:.2f} — the real branch is identifiable by bit length. This '
      f'is the ishaq bug: check that z is reduced mod n, not mod n^2.')

    d, d_crit = _two_sample_ks(real_bits, sim_bits)
    self.assertLess(
      d, d_crit,
      f'KS statistic {d:.4f} exceeds the 1% critical value {d_crit:.4f} — the '
      f'real and simulated response distributions are distinguishable')

  def test_11b_a_mod_n_squared_response_would_be_caught(self):
    """
    Guards the guard. If test 11 could not detect the ishaq bug, it would pass
    forever while proving nothing -- so here the bug is introduced deliberately
    and test 11's own criterion must reject it.
    """
    P = self.paillier
    kp = toy_keypair()
    pk, n, n2 = kp.pk, kp.pk.n, kp.pk.n2

    real_bits, sim_bits = [], []
    for _ in range(300):
      v = P.random_z_star_n(n)
      r = P.random_z_star_n(n)
      e = P.random_lt(P.CHALLENGE_MODULUS)

      real_bits.append(((r * pow(v, e, n)) % n2).bit_length())  # the BUG
      sim_bits.append(P.random_z_star_n(n).bit_length())

    self.assertGreater(
      abs(statistics.mean(real_bits) - statistics.mean(sim_bits)), 1.0,
      'test 11 would not have caught the ishaq bug')

    d, d_crit = _two_sample_ks(real_bits, sim_bits)
    self.assertGreater(d, d_crit, 'the KS arm of test 11 is not sensitive')

  # --- test 12 ------------------------------------------------------------

  def test_12_tamper_matrix(self):
    """
    Perturb each component of a proof independently; every perturbation must
    fail verification.
    """
    P = self.paillier
    c, r = self._encrypt(1)
    good = c.generate_disjunctive_encryption_proof(self.bits, 1, r, self.gen)
    self.assertTrue(
      c.verify_disjunctive_encryption_proof(self.bits, good, self.gen))

    for branch in (0, 1):
      for field in ('commitment', 'challenge', 'response'):
        tampered = P.PaillierZKDisjunctiveProof(
          [P.PaillierZKProof(p.commitment, p.challenge, p.response)
           for p in good.proofs])
        target = tampered.proofs[branch]
        setattr(target, field, getattr(target, field) + 1)

        self.assertFalse(
          c.verify_disjunctive_encryption_proof(self.bits, tampered, self.gen),
          f'tampering with proofs[{branch}].{field} still verified')

  def test_12b_tampering_with_the_statement_fails(self):
    """Perturbing u_j — i.e. presenting the proof against a different ciphertext."""
    c, r = self._encrypt(1)
    proof = c.generate_disjunctive_encryption_proof(self.bits, 1, r, self.gen)

    other, _ = self._encrypt(1)
    self.assertFalse(
      other.verify_disjunctive_encryption_proof(self.bits, proof, self.gen))

  def test_12c_permuting_the_real_index_fails(self):
    """
    Swapping the branch order breaks the challenge sum, because the hash is
    over the commitments in order.
    """
    c, r = self._encrypt(1)
    proof = c.generate_disjunctive_encryption_proof(self.bits, 1, r, self.gen)

    from helios.crypto import paillier as P
    permuted = P.PaillierZKDisjunctiveProof(list(reversed(proof.proofs)))
    self.assertFalse(
      c.verify_disjunctive_encryption_proof(self.bits, permuted, self.gen))

  def test_12d_wrong_branch_count_is_rejected(self):
    """A proof with fewer branches than plaintexts must not verify."""
    from helios.crypto import paillier as P

    c, r = self._encrypt(1)
    proof = c.generate_disjunctive_encryption_proof(self.bits, 1, r, self.gen)
    short = P.PaillierZKDisjunctiveProof(proof.proofs[:1])

    self.assertFalse(
      c.verify_disjunctive_encryption_proof(self.bits, short, self.gen))

  def test_12e_challenges_must_sum_to_the_hash(self):
    """
    The half of verification that makes it 1-out-of-L. Without it a prover
    could simulate every branch and prove nothing at all.
    """
    from helios.crypto import paillier as P

    c, r = self._encrypt(1)

    # Simulate BOTH branches: each transcript verifies individually.
    all_simulated = P.PaillierZKDisjunctiveProof(
      [c.simulate_encryption_proof(pt) for pt in self.bits])

    for pt, p in zip(self.bits, all_simulated.proofs):
      self.assertTrue(c.verify_encryption_proof(pt, p))

    self.assertFalse(
      c.verify_disjunctive_encryption_proof(self.bits, all_simulated, self.gen),
      'an all-simulated proof verified — the challenge-sum check is not '
      'binding, and ballot validity means nothing')

  # --- proof serialization ------------------------------------------------

  def test_disjunctive_proof_serializes_as_a_bare_array(self):
    """
    legacy/EGZKDisjunctiveProof overrides toDict to return ...['proofs'] rather
    than the wrapping object. The Paillier datatype must match, or
    individual_proofs changes shape and the harness's proof_bytes slice breaks
    silently — JSON.stringify(undefined) returns the 9-byte string "undefined"
    with no exception.
    """
    c, r = self._encrypt(1)
    proof = c.generate_disjunctive_encryption_proof(self.bits, 1, r, self.gen)

    ld = datatypes.LDObject.instantiate(
      proof, datatype='paillier/ZKDisjunctiveProof')
    serialized = ld.toDict()

    self.assertIsInstance(serialized, list, 'must be a bare array, not an object')
    self.assertEqual(len(serialized), 2)
    self.assertEqual(set(serialized[0]), {'commitment', 'challenge', 'response'})
    self.assertTrue(all(isinstance(v, str) for v in serialized[0].values()))

    back = datatypes.LDObject.fromDict(
      serialized, type_hint='paillier/ZKDisjunctiveProof')
    self.assertTrue(
      c.verify_disjunctive_encryption_proof(self.bits, back.wrapped_obj, self.gen),
      'a round-tripped proof no longer verifies')

  def test_proof_routes_through_the_elgamal_type_hint(self):
    """Trustee.decryption_proofs is typed arrayOf(arrayOf('legacy/EGZKProof'))."""
    c, _ = self._encrypt(3)
    _, proof = self.sk.decryption_factor_and_proof(c)

    serialized = datatypes.LDObject.instantiate(
      proof, datatype='legacy/EGZKProof').toDict()
    self.assertNotIsInstance(serialized['commitment'], dict)

    back = datatypes.LDObject.fromDict(serialized, type_hint='legacy/EGZKProof')
    self.assertIsInstance(back.wrapped_obj, self.paillier.PaillierZKProof)


class SchemeAgnosticWorkflowTests(unittest.TestCase):
  """
  Milestone B4 — workflows/homomorphic.py is scheme-agnostic.

  The claim in manuscript §9.2.2 is that both arms run the same pipeline. This
  makes that inspectable rather than argued: the tallying algorithms name no
  scheme, and the same functions produce a correct tally under either
  cryptosystem.
  """

  FACE = [{
    'answer_urls': [None] * 4,
    'answers': ['A', 'B', 'C', 'D'],
    'choice_type': 'approval',
    'max': 2,
    'min': 0,
    'question': 'q',
    'result_type': 'absolute',
    'short_name': 'q',
    'tally_type': 'homomorphic',
  }]

  def _election(self, pk):
    e = _FakeElection(self.FACE, pk)
    e.uuid = 'test-uuid'
    e.hash = 'test-hash'
    return e

  def test_homomorphic_py_names_no_scheme_in_the_algorithms(self):
    """
    The B4 gate. The only permitted references are inside
    _ciphertext_class_for, the deserialization fallback the build spec
    mandates for the case where self.public_key is not yet populated.
    """
    import inspect
    import re

    from helios.workflows import homomorphic

    source = inspect.getsource(homomorphic)
    fallback = inspect.getsource(homomorphic.Tally._ciphertext_class_for)
    outside = source.replace(fallback, '')

    # Strip comments before searching: the file explains the dispatch in prose.
    code = '\n'.join(line.split('#')[0] for line in outside.splitlines())

    offenders = re.findall(r'\b(algs\.\w+|EGCiphertext|EGPlaintext|'
                           r'crypto_elgamal|PaillierCiphertext)\b', code)
    self.assertEqual(
      [], offenders,
      f'homomorphic.py still names a scheme outside the documented '
      f'deserialization fallback: {sorted(set(offenders))}')

  def test_elgamal_adapters_are_installed_and_do_not_shadow(self):
    from helios.crypto import algs, elgamal

    for cls in (elgamal.PublicKey, algs.EGPublicKey):
      for name in ('generate_plaintexts', 'random_randomness',
                   'combine_randomness', 'tally_decoder',
                   'verify_decryption_proof', 'disjunctive_challenge_generator',
                   'ciphertext_class', 'randomness_identity'):
        self.assertTrue(hasattr(cls, name),
                        f'{cls.__name__} is missing {name}')

    self.assertEqual(elgamal.PublicKey.randomness_identity, 0,
                     'ElGamal accumulates randomness additively')

  def test_paillier_and_elgamal_expose_the_same_interface(self):
    """
    If the two public keys diverge on this interface, homomorphic.py works for
    one scheme and breaks for the other at a call site nobody tested.
    """
    from helios.crypto import elgamal, paillier

    interface = ('generate_plaintexts', 'random_randomness',
                 'combine_randomness', 'tally_decoder',
                 'verify_decryption_proof', 'disjunctive_challenge_generator',
                 'ciphertext_class', 'randomness_identity',
                 'encrypt_with_r', 'encrypt_return_r', 'encrypt')

    for name in interface:
      self.assertTrue(hasattr(elgamal.PublicKey, name), f'ElGamal lacks {name}')
      self.assertTrue(hasattr(paillier.PaillierPublicKey, name),
                      f'Paillier lacks {name}')

    # randomness_identity is a property on the Paillier side, because the value
    # depends on how randomness combines: multiplicative 1 for standard
    # Paillier, additive 0 under DJN §4.1 where the randomness is an exponent.
    self.assertEqual(medium_keypair().pk.randomness_identity, 1,
                     'standard Paillier accumulates randomness multiplicatively')
    self.assertEqual(
      paillier.PaillierKeyPair.from_primes(
        MEDIUM_P, MEDIUM_Q, use_djn_41=True).pk.randomness_identity, 0,
      'under DJN §4.1 randomness is an exponent and accumulates additively')

  def test_paillier_ballot_through_helios_encrypted_answer(self):
    """A Paillier ballot built by Helios's own EncryptedAnswer, and verified."""
    from helios.workflows.homomorphic import EncryptedAnswer

    kp = medium_keypair()
    election = self._election(kp.pk)

    ea = EncryptedAnswer.fromElectionAndAnswer(election, 0, [0, 2])

    self.assertEqual(len(ea.choices), 4)
    self.assertEqual(len(ea.individual_proofs), 4)
    self.assertEqual(len(ea.overall_proof.proofs), 3)  # L = max - min + 1
    self.assertTrue(ea.verify(kp.pk, min=0, max=2))

  def test_paillier_ballot_rejects_a_tampered_choice(self):
    from helios.workflows.homomorphic import EncryptedAnswer

    kp = medium_keypair()
    election = self._election(kp.pk)

    ea = EncryptedAnswer.fromElectionAndAnswer(election, 0, [0, 2])
    other = EncryptedAnswer.fromElectionAndAnswer(election, 0, [0, 2])
    ea.choices[1] = other.choices[1]

    self.assertFalse(ea.verify(kp.pk, min=0, max=2))

  def test_paillier_tally_end_to_end_through_helios_tally(self):
    """
    The whole point of B4: Helios's Tally, unmodified, producing a correct
    Paillier result -- with no DLogTable constructed anywhere.
    """
    from helios.crypto import paillier
    from helios.workflows.homomorphic import EncryptedAnswer, EncryptedVote, Tally

    kp = medium_keypair()
    election = self._election(kp.pk)

    tally = Tally(election=election)
    ballots = [[0, 2], [0, 1], [2, 3], [0, 2], [1, 1]]
    for answer in ballots:
      vote = EncryptedVote()
      vote.encrypted_answers = [
        EncryptedAnswer.fromElectionAndAnswer(election, 0, answer)]
      vote.election_hash = election.hash
      vote.election_uuid = election.uuid
      tally.add_vote(vote, verify_p=False)

    factors, proofs = tally.decryption_factors_and_proofs(kp.sk)
    result = tally.decrypt_from_factors([factors], kp.pk)

    # A=3 (ballots 0,1,3), B=2 (1,4 — note [1,1] selects B once), C=3, D=1
    self.assertEqual(result, [[3, 2, 3, 1]])

    self.assertTrue(tally.verify_decryption_proofs(
      factors, proofs, kp.pk,
      paillier.paillier_fiatshamir_challenge_generator))

  def test_paillier_tally_verifies_proofs_when_asked(self):
    """add_vote(verify_p=True) must accept a good ballot and reject a bad one."""
    from helios.workflows.homomorphic import EncryptedAnswer, EncryptedVote, Tally

    kp = medium_keypair()
    election = self._election(kp.pk)

    def make(answer):
      vote = EncryptedVote()
      vote.encrypted_answers = [
        EncryptedAnswer.fromElectionAndAnswer(election, 0, answer)]
      vote.election_hash = election.hash
      vote.election_uuid = election.uuid
      return vote

    tally = Tally(election=election)
    tally.add_vote(make([0, 1]), verify_p=True)
    self.assertEqual(tally.num_tallied, 1)

    # Swap in a choice from a different ballot: individually well-formed, but
    # its proof is bound to the other ciphertext.
    bad = make([0, 1])
    donor = make([0, 1])
    bad.encrypted_answers[0].choices[0] = donor.encrypted_answers[0].choices[0]

    with self.assertRaises(Exception):
      tally.add_vote(bad, verify_p=True)
    self.assertEqual(tally.num_tallied, 1, 'a bad vote was counted')

  def test_tally_deserialization_dispatches_on_shape_both_orderings(self):
    """
    Tally._process_value_in may run before self.public_key is set. Both
    orderings must work, for both schemes.
    """
    from helios.crypto import algs, paillier
    from helios.workflows.homomorphic import Tally

    eg_tally = [[{'alpha': '11', 'beta': '22'}]]
    pa_tally = [[{'c': '33'}]]

    # public_key absent -> dispatch on shape
    t = Tally()
    self.assertIs(t._ciphertext_class_for(eg_tally), algs.EGCiphertext)
    self.assertIs(t._ciphertext_class_for(pa_tally),
                  paillier.PaillierCiphertext)

    rebuilt = t._process_value_in('tally', pa_tally)
    self.assertIsInstance(rebuilt[0][0], paillier.PaillierCiphertext)
    self.assertEqual(rebuilt[0][0].c, 33)

    # public_key present -> it wins
    t2 = Tally()
    t2.public_key = medium_keypair().pk
    self.assertIs(t2._ciphertext_class_for(pa_tally),
                  paillier.PaillierCiphertext)

  def test_elgamal_tally_still_round_trips(self):
    """The control arm, through the same changed code path."""
    from helios.crypto import algs
    from helios.workflows.homomorphic import Tally

    t = Tally()
    rebuilt = t._process_value_in('tally', [[{'alpha': '11', 'beta': '22'}]])
    self.assertIsInstance(rebuilt[0][0], algs.EGCiphertext)
    self.assertEqual((rebuilt[0][0].alpha, rebuilt[0][0].beta), (11, 22))


class DJN41Tests(unittest.TestCase):
  """
  DJN §4.1 — the alternative encryption function, behind a flag.

  Replaces the blinding factor v^n (2048-bit exponent) with h^r for a fixed
  public h and a short r. The reason it costs no new proof theory is that h is
  ITSELF an n-th residue, so h^r stays an n-th power and Pi_root applies
  unchanged.

  Everything here is about proving that last sentence, and about proving the
  standard path is untouched.
  """

  def setUp(self):
    from helios.crypto import paillier
    self.paillier = paillier
    self.gen = paillier.paillier_disjunctive_challenge_generator

  def _kp(self, djn41):
    return self.paillier.PaillierKeyPair.from_primes(
      MEDIUM_P, MEDIUM_Q, use_djn_41=djn41)

  # --- the property the whole optimization rests on ------------------------

  def test_witness_is_a_valid_nth_root(self):
    """
    h = g'^(2n), so h^r = (g'^(2r))^n and the voter can compute the root with a
    SHORT exponent. If this fails, Pi_root has no witness and every ballot
    proof is unprovable.
    """
    kp = self._kp(True)
    pk = kp.pk

    for _ in range(20):
      r = pk.random_randomness()
      blinding = pow(pk.h, r, pk.n2)
      witness = pk.proof_witness(r)

      self.assertEqual(pow(witness, pk.n, pk.n2), blinding)
      self.assertEqual(math.gcd(witness, pk.n), 1, 'witness must be in Z*_n')

  def test_h_is_verifiably_an_nth_residue(self):
    kp = self._kp(True)
    pk = kp.pk
    self.assertEqual(pow(pk.g_prime, 2 * pk.n, pk.n2), pk.h)

  def test_short_exponent_is_actually_short(self):
    """
    The whole point. A regression that sampled Z*_n here would still verify and
    still decrypt -- it would simply be slower than the path it replaced, with
    nothing failing to say so.
    """
    from helios.crypto.paillier import DJN41_EXPONENT_BITS

    kp = self._kp(True)
    for _ in range(20):
      r = kp.pk.random_randomness()
      self.assertLess(r.bit_length(), DJN41_EXPONENT_BITS + 1)
      self.assertLess(r, 1 << DJN41_EXPONENT_BITS)

    # ...and encrypt_return_r must draw through random_randomness(), not
    # sample Z*_n directly. This is the bug that shipped and was caught.
    _, r = kp.pk.encrypt_return_r(self.paillier.PaillierPlaintext(1, kp.pk))
    self.assertLess(r.bit_length(), DJN41_EXPONENT_BITS + 1,
                    'encrypt_return_r is not using the short exponent')

  # --- correctness in the new mode ----------------------------------------

  def test_decryption_correctness(self):
    kp = self._kp(True)
    for m in (0, 1, 2, 12, 10 ** 6):
      c = kp.pk.encrypt(self.paillier.PaillierPlaintext(m, kp.pk))
      self.assertEqual(kp.sk.decryption_factor(c), m)
      self.assertEqual(kp.sk.decrypt_no_crt(c), m)

  def test_homomorphic_addition(self):
    kp = self._kp(True)
    P = self.paillier
    c1 = kp.pk.encrypt(P.PaillierPlaintext(7, kp.pk))
    c2 = kp.pk.encrypt(P.PaillierPlaintext(5, kp.pk))
    self.assertEqual(kp.sk.decryption_factor(c1 * c2), 12)

  def test_ballot_proofs_verify_in_both_modes(self):
    P = self.paillier

    for djn41 in (False, True):
      with self.subTest(djn41=djn41):
        kp = self._kp(djn41)
        pk = kp.pk

        plaintexts = pk.generate_plaintexts(0, 1)
        for bit in (0, 1):
          c, r = pk.encrypt_return_r(P.PaillierPlaintext(bit, pk))
          proof = c.generate_disjunctive_encryption_proof(
            plaintexts, bit, r, self.gen)
          self.assertTrue(
            c.verify_disjunctive_encryption_proof(plaintexts, proof, self.gen))

  def test_overall_proof_and_combined_witness(self):
    """
    The combined witness is where the two modes genuinely differ: standard
    multiplies witnesses mod n, §4.1 adds exponents.
    """
    P = self.paillier

    for djn41 in (False, True):
      with self.subTest(djn41=djn41):
        kp = self._kp(djn41)
        pk = kp.pk

        sum_plaintexts = pk.generate_plaintexts(0, 12)
        C, V, selected = 0, pk.randomness_identity, 0
        for i in range(20):
          bit = 1 if i < 5 else 0
          c, r = pk.encrypt_return_r(P.PaillierPlaintext(bit, pk))
          C = c * C
          V = pk.combine_randomness(V, r)
          selected += bit

        proof = C.generate_disjunctive_encryption_proof(
          sum_plaintexts, selected, V, self.gen)
        self.assertTrue(C.verify_disjunctive_encryption_proof(
          sum_plaintexts, proof, self.gen))
        self.assertEqual(kp.sk.decryption_factor(C), 5)

  def test_randomness_identity_matches_the_operation(self):
    self.assertEqual(self._kp(False).pk.randomness_identity, 1)  # multiplicative
    self.assertEqual(self._kp(True).pk.randomness_identity, 0)   # additive

  def test_soundness_still_holds(self):
    """A ciphertext of 2 must not be provable as 0-or-1 under §4.1 either."""
    P = self.paillier
    kp = self._kp(True)
    pk = kp.pk

    plaintexts = pk.generate_plaintexts(0, 1)
    c, r = pk.encrypt_return_r(P.PaillierPlaintext(2, pk))
    for claimed in (0, 1):
      proof = c.generate_disjunctive_encryption_proof(
        plaintexts, claimed, r, self.gen)
      self.assertFalse(
        c.verify_disjunctive_encryption_proof(plaintexts, proof, self.gen))

  def test_decryption_proof_unchanged(self):
    """
    The trustee still recovers an n-th root via u^(n^-1 mod lambda), because
    h^r is an n-th power. §2.8 needs no modification.
    """
    P = self.paillier
    kp = self._kp(True)

    c = kp.pk.encrypt(P.PaillierPlaintext(42, kp.pk))
    m, proof = kp.sk.decryption_factor_and_proof(c)

    self.assertEqual(m, 42)
    self.assertTrue(kp.pk.verify_decryption_proof(c, m, proof))
    self.assertFalse(kp.pk.verify_decryption_proof(c, 41, proof))

  # --- the standard path must be untouched ---------------------------------

  def test_standard_key_serialization_is_unchanged(self):
    """
    A standard key must NOT gain null h/g_prime fields. Stored elections and
    the B8 ballot-size canary both depend on this.
    """
    kp = self._kp(False)
    d = kp.pk.to_dict()

    self.assertEqual(set(d), {'n', 'g'})

    ld = datatypes.LDObject.instantiate(kp.pk, datatype='paillier/PublicKey')
    self.assertEqual(set(ld.toDict()), {'n', 'g'})

  def test_djn41_key_round_trips_with_its_parameters(self):
    kp = self._kp(True)
    d = kp.pk.to_dict()
    self.assertEqual(set(d), {'n', 'g', 'h', 'g_prime'})

    ld = datatypes.LDObject.instantiate(kp.pk, datatype='paillier/PublicKey')
    serialized = ld.toDict()
    self.assertEqual(set(serialized), {'n', 'g', 'h', 'g_prime'})

    back = datatypes.LDObject.fromDict(serialized,
                                       type_hint='paillier/PublicKey').wrapped_obj
    self.assertTrue(back.uses_djn_41, 'mode did not survive the round trip')
    self.assertEqual(back.h, kp.pk.h)
    self.assertEqual(back.g_prime, kp.pk.g_prime)

    # and it still encrypts correctly after the round trip
    from helios.crypto import paillier as P
    c, r = back.encrypt_return_r(P.PaillierPlaintext(3, back))
    self.assertEqual(kp.sk.decryption_factor(c), 3)

  def test_standard_key_round_trips_as_standard(self):
    kp = self._kp(False)
    ld = datatypes.LDObject.instantiate(kp.pk, datatype='paillier/PublicKey')
    back = datatypes.LDObject.fromDict(ld.toDict(),
                                       type_hint='paillier/PublicKey').wrapped_obj
    self.assertFalse(back.uses_djn_41)
    self.assertIsNone(back.h)

  def test_validation_rejects_a_forged_h(self):
    """
    h must be a verifiable n-th residue. A substituted h would make every
    ballot proof unprovable, and worse, would do so only at proving time.
    """
    from helios.crypto import paillier as P

    kp = P.Paillier(key_size=1024, use_djn_41=True).generate_keypair()
    kp.pk.validate_pk_params()   # must not raise

    kp.pk.h = (kp.pk.h + 1) % kp.pk.n2
    with self.assertRaises(Exception):
      kp.pk.validate_pk_params()

  def test_11_javascript_response_distribution_both_modes(self):
    """
    Test 11 (the ishaq canary) on the JAVASCRIPT side, in both modes.

    This is the test whose absence let a real ballot-secrecy bug ship. Test 11
    existed only in Python, and Python was correct; the booth's
    Paillier.Proof.generate/simulate drew their randomness from
    pk.randomRandomness(), which DJN §4.1 redefines from "uniform on Z*_n" to
    "a short exponent". Simulated branches came out ~510 bits against the real
    branch's ~2045, so the voter's selection was readable off the ballot.

    Every proof still verified and cross-language agreement still passed. Only
    a 12% shift in ballot size gave it away.
    """
    import shutil
    import subprocess
    import tempfile

    if not shutil.which('node'):
      self.skipTest('node not available')

    script = os.path.join(os.path.dirname(__file__), 'js_bridge',
                          'check_response_distribution.js')

    for djn41 in (False, True):
      with self.subTest(djn41=djn41):
        # 384-bit primes, not 1024. The property under test is structural --
        # do real and simulated responses have the same bit-length
        # distribution -- and it shows at any modulus WIDER THAN the DJN §4.1
        # short exponent. |n| = 640 against a 512-bit exponent still separates
        # the two by ~128 bits if the bug returns -- twenty-five times the 5-bit
        # threshold -- while keeping this fast enough to live in the default
        # suite rather than in a slow tier nobody runs.
        #
        # A toy key would NOT work: with |n| below 512 bits the short exponent
        # is the LONGER of the two and the comparison inverts.
        # Built from explicit primes rather than Paillier(key_size=...):
        # getStrongPrime refuses anything below 512 bits, and strong primes are
        # not what this test needs -- only a modulus wider than the short
        # exponent.
        from Crypto.Util import number
        from helios.crypto import paillier as P

        p = number.getPrime(320)
        q = number.getPrime(320)
        while q == p:
          q = number.getPrime(320)
        kp = P.PaillierKeyPair.from_primes(p, q, use_djn_41=djn41)

        self.assertGreater(kp.pk.n.bit_length(), P.DJN41_EXPONENT_BITS,
                           'modulus must exceed the short exponent or the '
                           'bit-length comparison is meaningless')

        with tempfile.NamedTemporaryFile('w', suffix='.json',
                                         delete=False) as f:
          json.dump(kp.pk.to_dict(), f)
          path = f.name
        try:
          proc = subprocess.run(['node', script, path, '12'],
                                capture_output=True, text=True, timeout=1800)
          try:
            verdict = json.loads(proc.stdout)
          except json.JSONDecodeError:
            self.fail(f'js bridge produced no verdict\n'
                      f'stderr: {proc.stderr[-2000:]}')
        finally:
          os.unlink(path)

        self.assertEqual(verdict['uses_djn_41'], djn41)
        self.assertTrue(verdict['all_verified'])

        # Threshold 5 bits, not 1. The bit length of a uniform value in Z*_n is
        # ~2047 with a variance near 2, so at 24 samples per group the standard
        # error of each mean is ~0.3 bits and a difference of ~1 bit is ordinary
        # noise. The failure this guards against moved the means ~1500 bits
        # apart. Five bits sits three orders of magnitude below the effect and
        # an order of magnitude above the noise, so it neither flakes nor
        # forgives.
        self.assertLess(
          verdict['delta_bits'], 5.0,
          f'JS real responses average {verdict["real_mean_bits"]:.1f} bits and '
          f'simulated {verdict["simulated_mean_bits"]:.1f} '
          f'(djn41={djn41}) — the real branch is identifiable by bit length '
          f'and ballot secrecy is gone. Check that Proof.generate and '
          f'Proof.simulate use randomZStarN(), not randomRandomness().')

        d, d_crit = _two_sample_ks(verdict['real_bits'],
                                   verdict['simulated_bits'])
        self.assertLess(d, d_crit,
                        f'KS statistic {d:.4f} exceeds critical {d_crit:.4f} '
                        f'(djn41={djn41})')

  def test_djn41_cross_language_agreement(self):
    """
    Test 9 extended to the new mode: a §4.1 ballot proof built by the booth's
    JavaScript must verify in Python, and vice versa.
    """
    import shutil
    import subprocess
    import tempfile

    if not shutil.which('node'):
      self.skipTest('node not available')

    P = self.paillier
    kp = self._kp(True)
    pk = kp.pk

    plaintexts = pk.generate_plaintexts(0, 1)
    c, r = pk.encrypt_return_r(P.PaillierPlaintext(1, pk))
    py_proof = c.generate_disjunctive_encryption_proof(
      plaintexts, 1, r, self.gen)

    payload = {
      'public_key': pk.to_dict(),
      'cases': [{'label': 'djn41 individual bit=1',
                 'ciphertext': c.to_dict(), 'min': 0, 'max': 1,
                 'real_index': 1, 'proof': py_proof.to_dict(),
                 'should_verify': True}],
      'generate': [{'label': 'js djn41 individual bit=1', 'kind': 'individual',
                    'min': 0, 'max': 1, 'real_index': 1},
                   {'label': 'js djn41 overall L=13', 'kind': 'overall',
                    'min': 0, 'max': 12, 'selected': 5, 'n_slots': 20}],
    }

    script = os.path.join(os.path.dirname(__file__), 'js_bridge',
                          'crosscheck_proofs.js')
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
      json.dump(payload, f)
      path = f.name
    try:
      proc = subprocess.run(['node', script, path],
                            capture_output=True, text=True, timeout=600)
      try:
        verdict = json.loads(proc.stdout)
      except json.JSONDecodeError:
        self.fail(f'js bridge produced no verdict\nstderr: {proc.stderr[-2000:]}')
    finally:
      os.unlink(path)

    for v in verdict['verified']:
      self.assertTrue(v['ok'], f'JS rejected a Python §4.1 proof: {v["label"]}')

    for g in verdict['generated']:
      self.assertTrue(g['self_verifies'], g['label'])

      ct = P.PaillierCiphertext.from_dict(g['ciphertext'], pk)
      pts = pk.generate_plaintexts(g['min'], g['max'])
      proof = P.PaillierZKDisjunctiveProof.from_dict(g['proof'])
      self.assertTrue(
        ct.verify_disjunctive_encryption_proof(pts, proof, self.gen),
        f'Python rejected a JS-generated §4.1 proof: {g["label"]}')


class PaillierKeyGenerationTests(unittest.TestCase):
  """Full-size key generation. Slow by nature — two 1024-bit strong primes."""

  def test_keygen_produces_a_valid_2048_bit_key(self):
    from Crypto.Util import number
    from helios.crypto import paillier

    kp = paillier.Paillier(key_size=1024).generate_keypair()

    self.assertEqual(number.size(kp.pk.n), 2048)
    self.assertEqual(kp.pk.g, kp.pk.n + 1)
    self.assertNotEqual(kp.sk.p, kp.sk.q)
    self.assertEqual(kp.sk.p * kp.sk.q, kp.pk.n)
    self.assertEqual(math.gcd(kp.sk.lambda_, kp.pk.n), 1)

    kp.pk.validate_pk_params()   # must not raise

    c = kp.pk.encrypt(paillier.PaillierPlaintext(12345, kp.pk))
    self.assertEqual(kp.sk.decryption_factor(c), 12345)

  def test_validate_pk_params_rejects_a_short_modulus(self):
    from helios.crypto import paillier

    with self.assertRaises(Exception):
      toy_keypair().pk.validate_pk_params()

    pk = paillier.PaillierPublicKey(n=1050589, g=999)
    with self.assertRaises(Exception):
      pk.validate_pk_params()


class SingleTrusteeEnforcementTests(unittest.TestCase):
  """
  Test 16, the crypto-level half (build spec §4.6, enforcement points 1 and 4).
  The model- and view-level halves land with B7.
  """

  def test_16a_public_keys_refuse_to_combine(self):
    a, b = toy_keypair().pk, medium_keypair().pk

    self.assertIs(a * 0, a)   # identities homomorphic_sum relies on
    self.assertIs(a * 1, a)

    with self.assertRaises(NotImplementedError) as ctx:
      a * b
    self.assertIn('§4.6', str(ctx.exception))

  def test_16d_decrypt_refuses_two_factor_sets(self):
    from helios.crypto import paillier

    kp = toy_keypair()
    c = kp.pk.encrypt(paillier.PaillierPlaintext(1, kp.pk))

    self.assertEqual(c.decrypt([5], kp.pk), 5)

    with self.assertRaises(NotImplementedError) as ctx:
      c.decrypt([5, 6], kp.pk)
    self.assertIn('§4.6', str(ctx.exception))

  def test_prove_sk_returns_none_not_an_empty_proof(self):
    """
    An empty proof object would verify vacuously, which is worse than an absent
    one. Trustee.pok is nullable, so None persists cleanly.
    """
    self.assertIsNone(toy_keypair().sk.prove_sk(lambda c: 1))


class ChallengeVectorTests(unittest.TestCase):
  """
  Milestone B1 (build spec §6.1) — cross-language challenge agreement.

  Risk 1 in the masterplan's damage-ordered list: a mismatch in hash-input
  formatting means every ballot verifies in the booth and every cast fails on
  the server, with the symptom far from the cause. This runs before either
  proof layer exists, because it is the cheapest way to discover the plan is
  wrong.
  """

  VECTORS_PATH = os.path.join(FIXTURE_DIR, 'challenge_vectors.json')

  def setUp(self):
    if not os.path.exists(self.VECTORS_PATH):
      self.skipTest(f'no fixture at {self.VECTORS_PATH} — generate it with '
                    f'`python -m helios.capture_challenge_vectors`')
    with open(self.VECTORS_PATH) as f:
      self.vectors = json.load(f)

  def test_fixture_covers_the_widths_that_matter(self):
    """
    A fixture that drifted to only easy cases would pass forever and prove
    nothing. L=13 is Q1's overall-proof width on the real 2025 NLE face; 1234
    digits is a full value mod n^2.
    """
    widths = {len(v['commitments']) for v in self.vectors}
    self.assertTrue({1, 2, 13} <= widths,
                    f'need L=1, 2 and 13; fixture has {sorted(widths)}')

    digits = {len(c) for v in self.vectors for c in v['commitments']}
    self.assertEqual(min(digits), 1)
    self.assertGreaterEqual(max(digits), 1234)

    self.assertGreaterEqual(len(self.vectors), 12,
                            'build spec §6.1 requires at least 12 cases')

  def test_python_reproduces_the_committed_vectors(self):
    """Guards the Python generator against silent change."""
    from helios.crypto.paillier import paillier_disjunctive_challenge_generator

    for v in self.vectors:
      commitments = [int(c) for c in v['commitments']]
      self.assertEqual(
        str(paillier_disjunctive_challenge_generator(commitments)),
        v['challenge'],
        f'Python challenge generator changed for: {v["label"]}')

  def test_fiatshamir_wrapper_delegates(self):
    from helios.crypto import paillier

    for v in self.vectors:
      if len(v['commitments']) != 1:
        continue
      a = int(v['commitments'][0])
      self.assertEqual(paillier.paillier_fiatshamir_challenge_generator(a),
                       paillier.paillier_disjunctive_challenge_generator([a]))

  def test_challenge_is_always_below_2_to_the_160(self):
    """
    The branch-challenge summation in the disjunctive proof reduces mod 2^160,
    and the soundness argument needs 2^t < the smallest prime factor of n.
    """
    from helios.crypto.paillier import CHALLENGE_MODULUS

    self.assertEqual(CHALLENGE_MODULUS, 1 << 160)
    for v in self.vectors:
      self.assertLess(int(v['challenge']), CHALLENGE_MODULUS)

  def test_javascript_agrees_with_python(self):
    """
    The B1 gate proper: the booth's OWN JavaScript, loaded the way
    boothworker-single.js loads it, must reproduce every vector.
    """
    import shutil
    import subprocess

    if not shutil.which('node'):
      self.skipTest('node not available')

    script = os.path.join(os.path.dirname(__file__), 'js_bridge',
                          'check_challenge_vectors.js')
    proc = subprocess.run(['node', script, self.VECTORS_PATH],
                          capture_output=True, text=True, timeout=120)

    try:
      verdict = json.loads(proc.stdout)
    except json.JSONDecodeError:
      self.fail(f'js bridge produced no verdict\n'
                f'stdout: {proc.stdout[:2000]}\nstderr: {proc.stderr[:2000]}')

    failures = [r for r in verdict['results'] if not r['ok']]
    self.assertEqual(
      [], failures,
      'Python and JavaScript disagree on the Fiat-Shamir challenge. Every '
      'ballot would verify in the booth and every cast would fail on the '
      'server. Do not proceed past B1 until this is resolved.')
    self.assertTrue(verdict['fiatshamir_wrapper_ok'])
    self.assertEqual(verdict['total'], len(self.vectors))


class CrossImplementationTests(unittest.TestCase):
  """
  Milestone B5, test 9 — Python and JavaScript agree on every proof type, both
  directions.

  Build spec §7: "Test 9 is the one that catches the bugs that matter. Helios's
  real pipeline generates proofs in the browser and verifies them on the server;
  if the two implementations disagree on challenge-hash input formatting -- byte
  order, separators, leading zeros -- everything silently fails at cast time."
  """

  def setUp(self):
    import shutil

    if not shutil.which('node'):
      self.skipTest('node not available')

    from helios.crypto import paillier
    self.paillier = paillier
    self.gen = paillier.paillier_disjunctive_challenge_generator
    self.kp = medium_keypair()
    self.pk, self.sk = self.kp.pk, self.kp.sk

  def _run_bridge(self, payload):
    import subprocess
    import tempfile

    script = os.path.join(os.path.dirname(__file__), 'js_bridge',
                          'crosscheck_proofs.js')

    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
      json.dump(payload, f)
      path = f.name

    try:
      proc = subprocess.run(['node', script, path],
                            capture_output=True, text=True, timeout=300)
      try:
        return json.loads(proc.stdout)
      except json.JSONDecodeError:
        self.fail(f'js bridge produced no verdict\n'
                  f'stdout: {proc.stdout[:2000]}\n'
                  f'stderr: {proc.stderr[:2000]}')
    finally:
      os.unlink(path)

  def _individual_case(self, label, bit, corrupt=False):
    P = self.paillier
    plaintexts = self.pk.generate_plaintexts(0, 1)
    c, r = self.pk.encrypt_return_r(P.PaillierPlaintext(bit, self.pk))
    proof = c.generate_disjunctive_encryption_proof(
      plaintexts, bit, r, self.gen)

    serialized = proof.to_dict()
    if corrupt:
      serialized[0]['response'] = str(int(serialized[0]['response']) + 1)

    return {'label': label, 'ciphertext': c.to_dict(), 'min': 0, 'max': 1,
            'real_index': bit, 'proof': serialized,
            'should_verify': not corrupt}

  def _overall_case(self, label, selected, n_slots, max_sel):
    P = self.paillier
    plaintexts = self.pk.generate_plaintexts(0, max_sel)

    C, V = 0, self.pk.randomness_identity
    for i in range(n_slots):
      bit = 1 if i < selected else 0
      c, r = self.pk.encrypt_return_r(P.PaillierPlaintext(bit, self.pk))
      C = c * C
      V = self.pk.combine_randomness(V, r)

    proof = C.generate_disjunctive_encryption_proof(
      plaintexts, selected, V, self.gen)

    return {'label': label, 'ciphertext': C.to_dict(), 'min': 0,
            'max': max_sel, 'real_index': selected,
            'proof': proof.to_dict(), 'should_verify': True}

  def test_09_cross_implementation_agreement(self):
    P = self.paillier

    # --- Python-generated, for JS to verify -------------------------------
    cases = [
      self._individual_case('individual bit=0', 0),
      self._individual_case('individual bit=1', 1),
      self._individual_case('individual bit=1, tampered', 1, corrupt=True),
      self._overall_case('overall L=2, 1 selected', 1, 4, 1),
      self._overall_case('overall L=13, 0 selected', 0, 20, 12),
      self._overall_case('overall L=13, 5 selected', 5, 20, 12),
      self._overall_case('overall L=13, 12 selected', 12, 20, 12),
    ]

    # --- decryption proofs, Python-generated ------------------------------
    ct, _ = self.pk.encrypt_return_r(P.PaillierPlaintext(7, self.pk))
    m, dproof = self.sk.decryption_factor_and_proof(ct)
    decryption_cases = [
      {'label': 'decryption proof, correct m', 'ciphertext': ct.to_dict(),
       'plaintext': str(m), 'proof': dproof.to_dict(), 'should_verify': True},
      {'label': 'decryption proof, wrong m', 'ciphertext': ct.to_dict(),
       'plaintext': str(m + 1), 'proof': dproof.to_dict(),
       'should_verify': False},
    ]

    # --- what JS should generate for Python to verify ---------------------
    generate = [
      {'label': 'js individual bit=0', 'kind': 'individual',
       'min': 0, 'max': 1, 'real_index': 0},
      {'label': 'js individual bit=1', 'kind': 'individual',
       'min': 0, 'max': 1, 'real_index': 1},
      {'label': 'js overall L=13, 5 selected', 'kind': 'overall',
       'min': 0, 'max': 12, 'selected': 5, 'n_slots': 20},
      {'label': 'js overall L=13, 0 selected', 'kind': 'overall',
       'min': 0, 'max': 12, 'selected': 0, 'n_slots': 20},
      {'label': 'js overall L=2, 1 selected', 'kind': 'overall',
       'min': 0, 'max': 1, 'selected': 1, 'n_slots': 4},
    ]

    verdict = self._run_bridge({
      'public_key': self.pk.to_dict(),
      'cases': cases,
      'decryption_cases': decryption_cases,
      'generate': generate,
    })

    # --- direction 1: JS verifying Python ---------------------------------
    for v in verdict['verified']:
      self.assertTrue(
        v['ok'],
        f'JS disagreed with Python on "{v["label"]}": expected '
        f'{v["expected"]}, got {v["got"]}')

    # --- direction 2: Python verifying JS ---------------------------------
    self.assertEqual(len(verdict['generated']), len(generate))

    for g in verdict['generated']:
      self.assertTrue(g['self_verifies'],
                      f'JS could not verify its own proof: {g["label"]}')

      ct = P.PaillierCiphertext.from_dict(g['ciphertext'], self.pk)
      plaintexts = self.pk.generate_plaintexts(g['min'], g['max'])
      proof = P.PaillierZKDisjunctiveProof.from_dict(g['proof'])

      self.assertTrue(
        ct.verify_disjunctive_encryption_proof(plaintexts, proof, self.gen),
        f'Python rejected a JS-generated proof: {g["label"]}. This is the '
        f'failure mode where every ballot verifies in the booth and every '
        f'cast fails on the server.')

  def test_09b_python_rejects_a_tampered_js_proof(self):
    """
    Guards the guard: if Python accepted anything the JS emitted, the direction-2
    assertion above would be vacuous.
    """
    P = self.paillier

    verdict = self._run_bridge({
      'public_key': self.pk.to_dict(),
      'cases': [],
      'generate': [{'label': 'js individual bit=1', 'kind': 'individual',
                    'min': 0, 'max': 1, 'real_index': 1}],
    })

    g = verdict['generated'][0]
    tampered = list(g['proof'])
    tampered[0] = dict(tampered[0])
    tampered[0]['response'] = str(int(tampered[0]['response']) + 1)

    ct = P.PaillierCiphertext.from_dict(g['ciphertext'], self.pk)
    plaintexts = self.pk.generate_plaintexts(0, 1)
    proof = P.PaillierZKDisjunctiveProof.from_dict(tampered)

    self.assertFalse(
      ct.verify_disjunctive_encryption_proof(plaintexts, proof, self.gen))

  def test_09c_serialized_shapes_match_between_languages(self):
    """
    A proof that verifies but serializes differently would still break the
    harness's proof_bytes slice and the bulletin board's stored representation.
    """
    verdict = self._run_bridge({
      'public_key': self.pk.to_dict(),
      'cases': [],
      'generate': [{'label': 'js individual', 'kind': 'individual',
                    'min': 0, 'max': 1, 'real_index': 1}],
    })

    js_proof = verdict['generated'][0]['proof']
    js_ct = verdict['generated'][0]['ciphertext']

    self.assertIsInstance(js_proof, list, 'disjunctive proof must be a bare array')
    self.assertEqual(set(js_ct), {'c'})
    self.assertEqual(set(js_proof[0]), {'commitment', 'challenge', 'response'})

    # Every value a decimal string, matching Helios convention.
    for field, value in js_proof[0].items():
      self.assertIsInstance(value, str, f'{field} must be a decimal string')
      self.assertTrue(value.lstrip('-').isdigit(),
                      f'{field} is not decimal: {value!r}')

    # And the Python side produces exactly the same key sets.
    from helios.crypto import paillier as P
    plaintexts = self.pk.generate_plaintexts(0, 1)
    c, r = self.pk.encrypt_return_r(P.PaillierPlaintext(1, self.pk))
    py_proof = c.generate_disjunctive_encryption_proof(
      plaintexts, 1, r, self.gen).to_dict()

    self.assertEqual(set(py_proof[0]), set(js_proof[0]))
    self.assertEqual(set(c.to_dict()), set(js_ct))


class ElectionIntegrationTests(TestCase):
  """
  Milestone B7 — the scheme reaches the model and view layers.

  Covers the model and view halves of test 16 (single-trustee enforcement); the
  crypto halves are in SingleTrusteeEnforcementTests. All four routes are
  checked, because each is a different way in and closing three of four closes
  nothing.
  """

  fixtures = ['users.json']

  def setUp(self):
    from helios_auth.models import User
    self.user = User.objects.get(user_id='ben@adida.net', user_type='google')

  def _election(self, scheme, short_name):
    from helios.models import Election
    import uuid as uuid_mod

    return Election.objects.create(
      admin=self.user, uuid=str(uuid_mod.uuid4()), short_name=short_name,
      name=f'{scheme} test', description='', election_type='election',
      crypto_scheme=scheme, cast_url='http://localhost/cast')

  # --- the column itself ---------------------------------------------------

  def test_crypto_scheme_defaults_to_elgamal(self):
    """
    Every existing election predates this column, so the default has to be the
    scheme they were actually run under.
    """
    from helios.models import Election
    import uuid as uuid_mod

    e = Election.objects.create(
      admin=self.user, uuid=str(uuid_mod.uuid4()), short_name='defaulted',
      name='n', description='', election_type='election',
      cast_url='http://localhost/cast')
    self.assertEqual(e.crypto_scheme, 'elgamal')

  # --- trustee generation --------------------------------------------------

  def test_generate_trustee_uses_the_right_cryptosystem(self):
    from helios.crypto import elgamal, paillier
    from helios.views import crypto_params_for

    eg = self._election('elgamal', 'wire-eg')
    eg.generate_trustee(crypto_params_for(eg))
    t = eg.get_helios_trustee()
    self.assertIsInstance(t.public_key, elgamal.PublicKey)
    self.assertIsNotNone(t.pok, 'ElGamal must still produce a Schnorr pok')

    pa = self._election('paillier', 'wire-pa')
    pa.generate_trustee(crypto_params_for(pa))
    t = pa.get_helios_trustee()
    self.assertIsInstance(t.public_key, paillier.PaillierPublicKey)
    self.assertEqual(t.public_key.g, t.public_key.n + 1)
    self.assertIsNone(t.pok,
                      'Paillier must store a null pok, not an empty proof '
                      'object — an empty proof verifies vacuously')

  def test_paillier_trustee_keys_survive_the_database(self):
    """
    The B0 dispatch under real persistence: Trustee.public_key and .secret_key
    are LDObjectFields whose static type hints say ElGamal.
    """
    from helios.crypto import paillier
    from helios.models import Trustee
    from helios.views import crypto_params_for

    pa = self._election('paillier', 'wire-pa-db')
    pa.generate_trustee(crypto_params_for(pa))
    original = pa.get_helios_trustee()

    reloaded = Trustee.objects.get(id=original.id)
    self.assertIsInstance(reloaded.public_key, paillier.PaillierPublicKey)
    self.assertIsInstance(reloaded.secret_key, paillier.PaillierSecretKey)
    self.assertEqual(reloaded.public_key.n, original.public_key.n)
    self.assertEqual(reloaded.secret_key.p, original.secret_key.p)
    self.assertEqual(reloaded.secret_key.lambda_, original.secret_key.lambda_)

    # and the recovered key still works
    ct = reloaded.public_key.encrypt(
      paillier.PaillierPlaintext(42, reloaded.public_key))
    self.assertEqual(reloaded.secret_key.decryption_factor(ct), 42)

  def test_election_public_key_survives_the_database(self):
    """Election.public_key is hinted 'legacy/EGPublicKey' at class-definition time."""
    from helios.crypto import paillier
    from helios.models import Election
    from helios.views import crypto_params_for

    pa = self._election('paillier', 'wire-pa-pk')
    pa.generate_trustee(crypto_params_for(pa))
    pa.public_key = pa.get_helios_trustee().public_key
    pa.save()

    reloaded = Election.objects.get(uuid=pa.uuid)
    self.assertEqual(reloaded.crypto_scheme, 'paillier')
    self.assertIsInstance(reloaded.public_key, paillier.PaillierPublicKey)

  # --- test 16, enforcement point 2 ---------------------------------------

  def test_16b_two_trustee_paillier_election_is_flagged_before_freeze(self):
    from helios.models import Trustee
    from helios.views import crypto_params_for
    import uuid as uuid_mod

    pa = self._election('paillier', 'wire-pa-two')
    pa.generate_trustee(crypto_params_for(pa))
    pa.questions = [{'answers': ['a', 'b'], 'max': 1, 'min': 0,
                     'question': 'q', 'short_name': 'q',
                     'tally_type': 'homomorphic', 'result_type': 'absolute',
                     'choice_type': 'approval', 'answer_urls': [None, None]}]
    pa.openreg = True
    pa.save()

    self.assertEqual([], [i for i in pa.issues_before_freeze
                          if i['type'] == 'trustees'])

    Trustee.objects.create(election=pa, uuid=str(uuid_mod.uuid4()),
                           name='Second', email='second@example.com')

    issues = [i for i in pa.issues_before_freeze if i['type'] == 'trustees']
    self.assertEqual(len(issues), 1, 'a second Paillier trustee was not flagged')
    self.assertIn('exactly one', issues[0]['action'])

  def test_16b_two_trustee_elgamal_election_is_still_fine(self):
    """The control arm must be unaffected: ElGamal supports many trustees."""
    from helios.models import Trustee
    from helios.views import crypto_params_for
    import uuid as uuid_mod

    eg = self._election('elgamal', 'wire-eg-two')
    eg.generate_trustee(crypto_params_for(eg))
    Trustee.objects.create(election=eg, uuid=str(uuid_mod.uuid4()),
                           name='Second', email='second@example.com')

    trustee_issues = [i for i in eg.issues_before_freeze
                      if i['type'] == 'trustees']
    self.assertEqual([], trustee_issues,
                     'a two-trustee ElGamal election must not be flagged')

  # --- test 16, enforcement point 3 ---------------------------------------

  def test_16c_trustee_routes_refuse_for_paillier(self):
    from django.core.exceptions import PermissionDenied
    from helios import views

    pa = self._election('paillier', 'wire-pa-routes')
    eg = self._election('elgamal', 'wire-eg-routes')

    # BOTH routes by which a second trustee can be added. Closing one of two
    # closes neither: new_trustee is the admin adding a trustee record, and
    # trustee_upload_pk is that trustee later supplying a key. An election that
    # refuses the first but accepts the second is still reachable.
    #
    # The views are decorated; the undecorated functions are called directly so
    # the test targets the refusal rather than the auth layer.
    routes = {}
    for name in ('new_trustee', 'trustee_upload_pk'):
      view = getattr(views, name)
      inner = getattr(view, '__wrapped__', None)
      self.assertIsNotNone(
        inner, f'{name} does not expose __wrapped__; this test would silently '
               f'stop checking enforcement point 3')
      routes[name] = inner

    with self.assertRaises(PermissionDenied):
      routes['new_trustee'](None, pa)

    # trustee_upload_pk is decorated with @trustee_check, so its inner takes
    # (request, election, trustee).
    with self.assertRaises(PermissionDenied):
      routes['trustee_upload_pk'](None, pa, None)

    # The control arm must still accept both routes. new_trustee on a GET
    # renders a template, so it is enough that it does not refuse.
    for name, fn in routes.items():
      try:
        fn(None, eg) if name == 'new_trustee' else fn(None, eg, None)
      except PermissionDenied:
        self.fail(f'{name} refused an ElGamal election — the control arm must '
                  f'keep its multi-trustee capability')
      except Exception:
        pass   # any other failure is the absent request/trustee, not a refusal

  def test_paillier_election_form_accepts_the_scheme(self):
    from helios.forms import ElectionForm

    form = ElectionForm(data={
      'short_name': 'form-pa', 'name': 'Form Paillier',
      'description': '', 'election_type': 'election',
      'crypto_scheme': 'paillier'})
    self.assertTrue(form.is_valid(), form.errors)
    self.assertEqual(form.cleaned_data['crypto_scheme'], 'paillier')

  def test_election_form_defaults_to_elgamal_when_omitted(self):
    """
    An existing caller that never heard of schemes -- including the harness
    before B9 -- must keep getting ElGamal.
    """
    from helios.forms import ElectionForm

    form = ElectionForm(data={
      'short_name': 'form-default', 'name': 'Form Default',
      'description': '', 'election_type': 'election'})
    self.assertTrue(form.is_valid(), form.errors)
    self.assertEqual(form.cleaned_data['crypto_scheme'], 'elgamal')

  # --- optimization ablations, per election --------------------------------

  def test_ablation_defaults(self):
    """
    DJN §4.1 off (it costs an extra assumption); CRT proofs on (it costs
    nothing). An existing election created before these columns existed must
    read the same way.
    """
    e = self._election('paillier', 'abl-default')
    self.assertFalse(e.paillier_use_djn41)
    self.assertTrue(e.paillier_use_crt_proofs)

  def test_ablation_config_is_scheme_aware(self):
    self.assertEqual(self._election('elgamal', 'abl-eg').ablation_config, {},
                     'ElGamal has no Paillier ablations to report')

    pa = self._election('paillier', 'abl-pa')
    pa.paillier_use_djn41 = True
    self.assertEqual(pa.ablation_config,
                     {'paillier_use_djn41': True,
                      'paillier_use_crt_proofs': True})

  def test_crypto_params_follow_the_election_not_a_global(self):
    """
    The switch is per election. A module-level setting could not be varied
    cell by cell, could not be recovered from a stored election, and could be
    set on the wrong process entirely.
    """
    from helios.views import crypto_params_for

    off = self._election('paillier', 'abl-off')
    on = self._election('paillier', 'abl-on')
    on.paillier_use_djn41 = True

    self.assertFalse(crypto_params_for(off).use_djn_41)
    self.assertTrue(crypto_params_for(on).use_djn_41)

    # ...and the generated key really carries it
    on.generate_trustee(crypto_params_for(on))
    self.assertTrue(on.get_helios_trustee().public_key.uses_djn_41)

    off.generate_trustee(crypto_params_for(off))
    self.assertFalse(off.get_helios_trustee().public_key.uses_djn_41)

  def test_crt_proof_setting_reaches_the_secret_key(self):
    """
    The secret key is deserialized fresh from the database on every access, so
    there is no live object that could have carried this from key generation.
    helios_trustee_decrypt has to apply it at use time.
    """
    from helios.models import CastVote, Voter
    from helios.views import crypto_params_for
    from helios.workflows.homomorphic import EncryptedVote

    for use_crt in (True, False):
      with self.subTest(use_crt=use_crt):
        e = self._election('paillier', f'abl-crt-{use_crt}')
        e.paillier_use_crt_proofs = use_crt
        e.generate_trustee(crypto_params_for(e))
        e.questions = [{'answers': ['A', 'B'], 'answer_urls': [None, None],
                        'max': 1, 'min': 0, 'question': 'q',
                        'short_name': 'q', 'tally_type': 'homomorphic',
                        'result_type': 'absolute',
                        'choice_type': 'approval'}]
        e.openreg = True
        e.save()
        e.freeze()

        voter = Voter.objects.create(
          election=e, uuid=f'abl-{use_crt}', voter_login_id='v',
          voter_name='V', voter_email='v@example.com')
        vote = EncryptedVote.fromElectionAndAnswers(e, [[0]])
        cv = CastVote(voter=voter, vote=vote, vote_hash=vote.hash,
                      cast_at=datetime.datetime.utcnow())
        cv.save()
        voter.store_vote(cv)

        e.compute_tally()
        e.helios_trustee_decrypt()
        e.combine_decryptions()

        # correct either way -- CRT is an acceleration, not a different protocol
        self.assertEqual(e.result, [[1, 0]])
        self.assertTrue(e.get_helios_trustee().verify_decryption_proofs())

  def test_election_form_carries_the_ablations(self):
    from helios.forms import ElectionForm

    form = ElectionForm(data={
      'short_name': 'abl-form', 'name': 'Ablation', 'description': '',
      'election_type': 'election', 'crypto_scheme': 'paillier',
      'paillier_use_djn41': '1', 'paillier_use_crt_proofs': '0'})
    self.assertTrue(form.is_valid(), form.errors)
    self.assertTrue(form.cleaned_data['paillier_use_djn41'])
    self.assertFalse(form.cleaned_data['paillier_use_crt_proofs'])

  def test_ablation_flags_parse_every_falsey_spelling(self):
    """
    Regression: posting '0' to turn a flag OFF used to turn it ON.

    forms.BooleanField uses CheckboxInput, whose value_from_datadict recognises
    only the literal strings "true"/"false" and otherwise returns bool(value) --
    and bool('0') is True. So an ablation cell asking for djn41=False created an
    election with djn41=True, while stamping False on its own records.

    The form reported valid, the election ran, the tally was correct, and the
    only symptom was that the A and B cells produced identical numbers.
    """
    from helios.forms import ElectionForm

    base = {'short_name': 'x', 'name': 'X', 'description': '',
            'election_type': 'election', 'crypto_scheme': 'paillier'}

    for spelling in ('0', 'false', 'False', '', 'off', 'no'):
      form = ElectionForm(data={**base, 'paillier_use_djn41': spelling})
      self.assertTrue(form.is_valid(), form.errors)
      self.assertFalse(form.cleaned_data['paillier_use_djn41'],
                       f'{spelling!r} should disable the flag, not enable it')

    for spelling in ('1', 'true', 'True', 'on', 'yes'):
      form = ElectionForm(data={**base, 'paillier_use_djn41': spelling})
      self.assertTrue(form.is_valid(), form.errors)
      self.assertTrue(form.cleaned_data['paillier_use_djn41'],
                      f'{spelling!r} should enable the flag')

    # ...and the same for the flag whose default is True
    for spelling in ('0', 'false', ''):
      form = ElectionForm(data={**base, 'paillier_use_crt_proofs': spelling})
      self.assertTrue(form.is_valid(), form.errors)
      self.assertFalse(form.cleaned_data['paillier_use_crt_proofs'],
                       f'{spelling!r} should disable CRT proofs')

  def test_crt_proofs_defaults_true_when_the_field_is_absent(self):
    """
    An unchecked HTML checkbox submits nothing, which Django reads as False.
    Without the custom clean, a caller that never heard of this field would
    silently disable an optimization that costs nothing.
    """
    from helios.forms import ElectionForm

    form = ElectionForm(data={
      'short_name': 'abl-absent', 'name': 'Absent', 'description': '',
      'election_type': 'election', 'crypto_scheme': 'paillier'})
    self.assertTrue(form.is_valid(), form.errors)
    self.assertTrue(form.cleaned_data['paillier_use_crt_proofs'])
    self.assertFalse(form.cleaned_data['paillier_use_djn41'])

  # --- the whole pipeline, through the model layer -------------------------

  def test_paillier_election_freezes_tallies_and_decrypts(self):
    """
    Freeze -> vote -> tally -> decrypt, using Helios's own model methods and the
    same call graph an ElGamal election takes.
    """
    from helios.models import CastVote, Voter
    from helios.views import crypto_params_for
    from helios.workflows.homomorphic import EncryptedVote

    for scheme in ('elgamal', 'paillier'):
      with self.subTest(scheme=scheme):
        e = self._election(scheme, f'e2e-{scheme}')
        e.generate_trustee(crypto_params_for(e))
        e.questions = [{
          'answers': ['A', 'B', 'C'], 'answer_urls': [None] * 3,
          'max': 2, 'min': 0, 'question': 'pick up to 2',
          'short_name': 'q1', 'tally_type': 'homomorphic',
          'result_type': 'absolute', 'choice_type': 'approval'}]
        e.openreg = True
        e.save()

        self.assertEqual([], e.issues_before_freeze, e.issues_before_freeze)
        e.freeze()
        self.assertIsNotNone(e.frozen_at)
        self.assertIsNotNone(e.public_key)

        ballots = [[0], [0, 1], [2], [0, 2]]
        for i, answer in enumerate(ballots):
          voter = Voter.objects.create(
            election=e, uuid=f'{scheme}-voter-{i}',
            voter_login_id=f'v{i}', voter_name=f'Voter {i}',
            voter_email=f'v{i}@example.com')
          vote = EncryptedVote.fromElectionAndAnswers(e, [answer])
          cv = CastVote(voter=voter, vote=vote, vote_hash=vote.hash,
                        cast_at=datetime.datetime.utcnow())
          self.assertTrue(vote.verify(e), f'{scheme} ballot {i} failed to verify')
          cv.save()
          voter.store_vote(cv)

        e.compute_tally()
        self.assertEqual(e.encrypted_tally.num_tallied, len(ballots))

        e.helios_trustee_decrypt()
        e.combine_decryptions()

        # A=3, B=1, C=2
        self.assertEqual(e.result, [[3, 1, 2]], f'{scheme} tally is wrong')

        trustee = e.get_helios_trustee()
        self.assertTrue(trustee.verify_decryption_proofs(),
                        f'{scheme} decryption proofs did not verify')


class BoothLoaderTests(unittest.TestCase):
  """
  Milestone B6 — both loaders carry the Paillier code.

  The booth has two of them (build spec §1.6): heliosbooth/vote.html has every
  individual <script> commented out and loads a compiled bundle, while
  boothworker-single.js importScripts the individual files. The measurement
  harness drives the MAIN THREAD via vote.html, so it exercises the bundle; a
  real voter's encryption runs in the WORKER, off the individual files.

  Adding paillier.js to one and not the other fails silently, and which half you
  notice depends on which way you happen to test.

  The bundle itself is exercised in a real browser by
  helios/benchmarks/ballot_size_canary.py, not here: the bundle carries jQuery,
  which touches `document` at load, so checking it under Node would mean faking
  a DOM and then testing the fake. That script also takes minutes, which does
  not belong in the default suite.
  """

  BOOTH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       'heliosbooth')

  def test_worker_importscripts_loads_paillier(self):
    with open(os.path.join(self.BOOTH, 'boothworker-single.js')) as f:
      source = f.read()

    self.assertIn('js/jscrypto/paillier.js', source,
                  'the Web Worker — what a real voter uses — does not load '
                  'paillier.js')
    self.assertIn('js/jscrypto/scheme_adapters.js', source)

    # Order matters: scheme_adapters.js attaches methods onto ElGamal.PublicKey
    # and Paillier.PublicKey, so both must already be defined.
    self.assertLess(source.index('elgamal.js'), source.index('paillier.js'))
    self.assertLess(source.index('paillier.js'),
                    source.index('scheme_adapters.js'))
    self.assertLess(source.index('scheme_adapters.js'), source.index('helios.js'))

  def test_vote_html_references_the_rebuilt_bundle(self):
    with open(os.path.join(self.BOOTH, 'vote.html')) as f:
      source = f.read()

    self.assertIn('20260907-helios-booth-compressed.js', source,
                  'vote.html still points at a bundle without the Paillier layer')

  def test_bundle_contains_the_paillier_layer(self):
    """
    The bundle is what the harness measures. If paillier.js were missing from
    it, every Paillier encryption measurement would come from a ballot the
    booth could not actually have produced.
    """
    bundle = os.path.join(self.BOOTH, 'js',
                          '20260907-helios-booth-compressed.js')
    self.assertTrue(os.path.exists(bundle), 'rebuilt bundle is missing')

    with open(bundle) as f:
      source = f.read()

    for marker in ('Paillier', 'disjunctive_challenge_generator',
                   'CRYPTO', 'publicKeyFromJSONObject'):
      self.assertIn(marker, source, f'bundle lacks {marker}')

  def test_worker_path_builds_ballots_for_both_schemes(self):
    """
    The worker path, driven under Node exactly as boothworker-single.js loads
    it, must build a well-formed ballot under either cryptosystem.
    """
    import shutil
    import subprocess
    import tempfile

    if not shutil.which('node'):
      self.skipTest('node not available')

    from helios import datatypes
    from helios.crypto import paillier
    from helios.views import ELGAMAL_PARAMS

    face = [{
      'answer_urls': [None] * 4, 'answers': ['A', 'B', 'C', 'D'],
      'choice_type': 'approval', 'max': 2, 'min': 0, 'question': 'q',
      'result_type': 'absolute', 'short_name': 'q',
      'tally_type': 'homomorphic',
    }]

    def election(pk_dict):
      return {'public_key': pk_dict, 'questions': face, 'uuid': 'u',
              'name': 'n', 'short_name': 's', 'cast_url': '', 'description': '',
              'frozen_at': None, 'openreg': False, 'use_voter_aliases': False,
              'voters_hash': None, 'voting_ends_at': None,
              'voting_starts_at': None}

    cases = {
      'elgamal': (election(datatypes.LDObject.instantiate(
        ELGAMAL_PARAMS.generate_keypair().pk,
        datatype='legacy/EGPublicKey').toDict()), {'alpha', 'beta'}),
      'paillier': (election(
        paillier.PaillierKeyPair.from_primes(MEDIUM_P, MEDIUM_Q).pk.to_dict()),
        {'c'}),
    }

    script = os.path.join(os.path.dirname(__file__), 'js_bridge',
                          'check_loaders.js')

    for scheme, (el, expected_keys) in cases.items():
      with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
        json.dump(el, f)
        path = f.name
      try:
        proc = subprocess.run(['node', script, path, '[0,2]', '--worker-only'],
                              capture_output=True, text=True, timeout=600)
        try:
          verdict = json.loads(proc.stdout)
        except json.JSONDecodeError:
          self.fail(f'{scheme}: loader check produced no verdict\n'
                    f'stderr: {proc.stderr[-2000:]}')
      finally:
        os.unlink(path)

      shape = verdict['worker_shape']
      self.assertEqual(set(shape['choice_keys']), expected_keys,
                       f'{scheme} ballot has the wrong ciphertext shape')
      self.assertEqual(shape['n_choices'], 4)
      self.assertEqual(shape['individual_branches'], [2, 2, 2, 2])
      self.assertEqual(shape['overall_branches'], 3)  # L = max - min + 1
      self.assertEqual(set(shape['proof_keys']),
                       {'commitment', 'challenge', 'response'})


class DatatypeDispatchSpikeTests(unittest.TestCase):
  """
  Milestone B0 (build spec §5.1, masterplan §2.4a).

  Nine LDObjectField type hints are static, so a Paillier object stored in
  Election.public_key or CastVote.vote would be handed to the ElGamal
  deserializer. This milestone proves a second cryptosystem can round-trip
  through those fields before any cryptography is written -- the cheapest
  possible way to discover the integration plan is wrong.
  """

  def test_scheme_ambiguous_set_matches_the_static_hints(self):
    """
    The ambiguous set must cover every ElGamal-specific datatype the nine
    static hints can reach, or a Paillier object routed through an uncovered
    one is silently handed to the ElGamal deserializer.
    """
    self.assertEqual(
      datatypes.SCHEME_AMBIGUOUS_DATATYPES,
      frozenset({'legacy/EGPublicKey', 'legacy/EGSecretKey',
                 'legacy/EGCiphertext', 'legacy/EGZKProof',
                 'legacy/EGZKDisjunctiveProof', 'legacy/DLogProof'}))

  def test_shape_dispatch_routes_by_field_set(self):
    resolve = datatypes._resolve_by_shape

    # ElGamal shapes are left exactly as they are.
    self.assertEqual(
      resolve({'y': '1', 'p': '2', 'g': '3', 'q': '4'}, 'legacy/EGPublicKey'),
      'legacy/EGPublicKey')
    self.assertEqual(
      resolve({'alpha': '1', 'beta': '2'}, 'legacy/EGCiphertext'),
      'legacy/EGCiphertext')
    self.assertEqual(
      resolve({'commitment': {'A': '1', 'B': '2'}, 'challenge': '3',
               'response': '4'}, 'legacy/EGZKProof'),
      'legacy/EGZKProof')

    # Paillier shapes are re-routed.
    self.assertEqual(resolve({'n': '1', 'g': '2'}, 'legacy/EGPublicKey'),
                     'paillier/PublicKey')
    self.assertEqual(resolve({'c': '1'}, 'legacy/EGCiphertext'),
                     'paillier/Ciphertext')
    self.assertEqual(
      resolve({'commitment': '1', 'challenge': '2', 'response': '3'},
              'legacy/EGZKProof'),
      'paillier/ZKProof')
    self.assertEqual(
      resolve([{'commitment': '1', 'challenge': '2', 'response': '3'}],
              'legacy/EGZKDisjunctiveProof'),
      'paillier/ZKDisjunctiveProof')

  def test_non_ambiguous_hints_pass_through_untouched(self):
    """A hint outside the six is never rewritten, whatever the dict looks like."""
    resolve = datatypes._resolve_by_shape
    for hint in ('legacy/EncryptedVote', 'legacy/Tally', 'core/BigInteger',
                 'legacy/ShortCastVote', '2011/01/Trustee'):
      self.assertEqual(resolve({'c': '1', 'n': '2'}, hint), hint)

  def test_instantiate_does_not_break_includeRandomness(self):
    """
    Regression guard on the precedence change.

    Both design documents prescribe a blanket flip: the wrapped object's own
    datatype always wins. homomorphic.EncryptedVote declares
    datatype='legacy/EncryptedVote', so under a blanket flip this call would be
    overridden and the voter-facing randomness silently dropped.
    """
    from helios.workflows import homomorphic

    ev = homomorphic.EncryptedVote()
    ev.encrypted_answers, ev.election_hash, ev.election_uuid = [], 'h', 'u'

    ld = datatypes.LDObject.instantiate(
      ev, datatype='legacy/EncryptedVoteWithRandomness')
    self.assertEqual(type(ld).__name__, 'EncryptedVoteWithRandomness')
    self.assertEqual(ld.STRUCTURED_FIELDS['answers'].ELEMENT_TYPE,
                     'legacy/EncryptedAnswerWithRandomness')

  def test_instantiate_still_honours_a_declared_datatype(self):
    """The half of the flip that is actually needed: no hint at all."""
    from helios.workflows import homomorphic

    ev = homomorphic.EncryptedVote()
    ev.encrypted_answers, ev.election_hash, ev.election_uuid = [], 'h', 'u'
    ld = datatypes.LDObject.instantiate(ev)
    self.assertEqual(type(ld).__name__, 'EncryptedVote')

  def test_instantiate_lets_a_declared_datatype_win_over_an_ambiguous_hint(self):
    """
    The other half: an object that declares a Paillier datatype must not be
    serialized by the ElGamal writer just because the field hint says so.
    """
    with _spike_datatypes():
      obj = _SpikeKey(n=7, g=8)
      ld = datatypes.LDObject.instantiate(obj, datatype='legacy/EGPublicKey')
      self.assertEqual(ld.datatype, 'spike/SpikeKey')
      self.assertEqual(ld.toDict(), {'n': '7', 'g': '8'})

  def test_non_elgamal_object_roundtrips_through_LDObjectField(self):
    """
    The B0 gate itself: save -> reload -> compare, through the real Django
    field, using the real static ElGamal type hint that a Paillier public key
    would be stored under.
    """
    from helios.datatypes.djangofield import LDObjectField

    with _spike_datatypes():
      field = LDObjectField(type_hint='legacy/EGPublicKey')

      original = _SpikeKey(n=1234567890123456789, g=1234567890123456790)
      stored = field.get_prep_value(original)

      self.assertIn('"n"', stored)
      self.assertNotIn('"y"', stored)  # not serialized as ElGamal

      reloaded = field.from_db_value(stored)
      self.assertIsInstance(reloaded, _SpikeKey)
      self.assertEqual(reloaded.n, original.n)
      self.assertEqual(reloaded.g, original.g)

  def test_elgamal_public_key_still_roundtrips_through_the_same_field(self):
    """The same field, unchanged, must still carry an ElGamal key."""
    from helios.crypto import elgamal
    from helios.datatypes.djangofield import LDObjectField
    from helios.views import ELGAMAL_PARAMS

    field = LDObjectField(type_hint='legacy/EGPublicKey')

    pk = elgamal.PublicKey()
    pk.p, pk.q, pk.g = ELGAMAL_PARAMS.p, ELGAMAL_PARAMS.q, ELGAMAL_PARAMS.g
    pk.y = pow(pk.g, 12345, pk.p)

    reloaded = field.from_db_value(field.get_prep_value(pk))
    self.assertEqual((reloaded.y, reloaded.p, reloaded.g, reloaded.q),
                     (pk.y, pk.p, pk.g, pk.q))


class _SpikeKey:
  """
  A stand-in for a Paillier public key, shaped like one ({n, g}) and declaring
  its own datatype, but with no cryptography behind it. B0 runs before
  helios/crypto/paillier.py exists, and the question it answers is purely about
  dispatch.
  """
  datatype = 'spike/SpikeKey'

  def __init__(self, n=None, g=None):
    self.n = n
    self.g = g


@contextlib.contextmanager
def _spike_datatypes():
  """
  Register a throwaway `helios.datatypes.spike` module for the duration.

  get_class() resolves a datatype string by importlib.import_module, which
  consults sys.modules first -- so injecting the module there is enough, and no
  placeholder file has to be committed and later deleted.
  """
  import sys
  import types

  mod = types.ModuleType('helios.datatypes.spike')

  class SpikeKey(datatypes.LDObject):
    WRAPPED_OBJ_CLASS = _SpikeKey
    USE_JSON_LD = False
    FIELDS = ['n', 'g']
    STRUCTURED_FIELDS = {'n': 'core/BigInteger', 'g': 'core/BigInteger'}

  mod.SpikeKey = SpikeKey
  sys.modules['helios.datatypes.spike'] = mod

  # Route the ambiguous ElGamal hint to the spike when the dict is {n, g}.
  original = datatypes._resolve_by_shape

  def patched(d, ld_type):
    resolved = original(d, ld_type)
    return 'spike/SpikeKey' if resolved == 'paillier/PublicKey' else resolved

  datatypes._resolve_by_shape = patched
  try:
    yield
  finally:
    datatypes._resolve_by_shape = original
    sys.modules.pop('helios.datatypes.spike', None)


class BigIntegerZeroTests(unittest.TestCase):
  """
  Build spec §1.3. core/BigInteger serialized 0 as null, because `if
  self.wrapped_obj` is false for 0.

  Harmless for ElGamal, where a decryption factor is a group element in [1, p)
  and never zero. Fatal for Paillier, where the decryption factor IS the
  plaintext tally and a candidate with zero votes produces exactly 0.
  Trustee.decryption_factors is typed arrayOf(arrayOf('core/BigInteger')), so a
  zero tally would round-trip as null and the result would be wrong for exactly
  the candidates nobody voted for.
  """

  def test_bigint_zero_roundtrips(self):
    from helios.datatypes.core import BigInteger

    self.assertEqual(BigInteger(0).toDict(), '0',
                     'zero must serialize as "0", not null')

    reloaded = datatypes.LDObject.fromDict('0', type_hint='core/BigInteger')
    self.assertEqual(reloaded.wrapped_obj, 0)

  def test_bigint_nonzero_unaffected(self):
    from helios.datatypes.core import BigInteger

    self.assertEqual(BigInteger(1).toDict(), '1')
    self.assertEqual(BigInteger(12345678901234567890).toDict(),
                     '12345678901234567890')

  def test_bigint_none_still_null(self):
    """None is genuinely absent and must stay null — only 0 was misclassified."""
    from helios.datatypes.core import BigInteger

    self.assertIsNone(BigInteger(None).toDict())

  def test_decryption_factors_roundtrip_with_a_zero_tally(self):
    """
    The §1.3 bug in the shape it would actually have bitten: a per-trustee
    decryption-factor matrix in which one candidate received no votes.
    """
    factors = [[5, 0, 7], [0, 0, 3]]
    type_hint = datatypes.arrayOf(datatypes.arrayOf('core/BigInteger'))

    ld = datatypes.LDObject.instantiate(factors, datatype=type_hint)
    serialized = ld.toDict()

    self.assertEqual(serialized, [['5', '0', '7'], ['0', '0', '3']],
                     'a zero decryption factor must survive serialization')

    back = datatypes.LDObject.fromDict(serialized, type_hint=type_hint)
    self.assertEqual(back.wrapped_obj, factors)
