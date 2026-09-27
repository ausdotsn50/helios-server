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

from django.test import TestCase, TransactionTestCase, tag

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

# DJN §4.1 needs SAFE primes, and 1024-bit safe primes take seconds to tens of
# seconds each to generate, so every DJN test shares this one fixed pair of
# 512-bit safe primes, giving |n| = 1024. Made once with
#
#     Crypto.Math.Primality.generate_probable_safe_prime(exact_bits=512)
#
# redrawn until p*q had exactly 1024 bits, then checked: p = q = 3 (mod 4),
# gcd(p-1, q-1) = 2, and p, q, (p-1)/2 and (q-1)/2 all prime.
# DJN41KeyTests.test_the_fixed_primes_meet_the_djn41_conditions re-checks them.
DJN_P = 13168689723100660585685922549334792506527228763451163683969222265825863724246852232201259732581751830544365565680414276277884873986403685288800169781242727
DJN_Q = 8645116233607178444096843766139414926699103144057498079660518867117481230248921238509961864803698923112142027274849449064395322551689148313525971278196299


def toy_keypair():
  from helios.crypto.paillier import PaillierKeyPair
  return PaillierKeyPair.from_primes(TOY_P, TOY_Q)


def medium_keypair():
  from helios.crypto.paillier import PaillierKeyPair
  return PaillierKeyPair.from_primes(MEDIUM_P, MEDIUM_Q)


def djn_keypair(mode):
  """A key on the fixed safe primes, in any of the three modes."""
  from helios.crypto.paillier import PaillierKeyPair
  return PaillierKeyPair.from_primes(DJN_P, DJN_Q, djn41_mode=mode)


@contextlib.contextmanager
def _validation_floor(bits):
  """
  Lower validate_pk_params's minimum modulus width for the duration. A 1024-bit
  test key would otherwise be refused for its length before any DJN §4.1 check
  ran, and a test of those checks would pass without reaching them.
  """
  from unittest import mock
  from helios.crypto import paillier

  with mock.patch.object(paillier, 'MIN_MODULUS_BITS', bits):
    yield


def _run_node_bridge(test, script, payload, *args):
  """Run helios/js_bridge/<script> on a JSON payload; return its verdict."""
  import subprocess
  import tempfile

  script_path = os.path.join(os.path.dirname(__file__), 'js_bridge', script)
  with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
    json.dump(payload, f)
    path = f.name

  try:
    proc = subprocess.run(['node', script_path, path, *args],
                          capture_output=True, text=True, timeout=600)
    try:
      return json.loads(proc.stdout)
    except json.JSONDecodeError:
      test.fail(f'js bridge {script} produced no verdict\n'
                f'stderr: {proc.stderr[-2000:]}')
  finally:
    os.unlink(path)


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
    (pq)^2, which vanishes mod p^2. Paillier (1999) §7 gives h_p only in its
    general form, L_p(g^(p-1) mod p^2)^-1, so the closed form is derived rather
    than quoted, and worth checking.
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


def _forge_oversized_challenge_proof(ciphertext, plaintexts, true_m, witness,
                                     challenge_generator):
  """
  A disjunctive proof that `ciphertext` encrypts one of `plaintexts`, for a
  ciphertext that encrypts none of them -- it encrypts `true_m`.

  Every branch j is false: u_j = (1 + d_j*n) * v^n with d_j = true_m - m_j != 0.
  A false branch still satisfies z^n = a * u^e (mod n^2) for EVERY e congruent
  to e_j* mod n, because the (1 + t_j*n) planted in the commitment cancels the
  (1 + e*d_j*n) that u_j^e carries:

      a_j = s_j^n * (1 + t_j*n) mod n^2,   e_j* = -t_j * d_j^-1 mod n,
      z_j = s_j * v^e_j mod n

  The challenges still have to sum to the hash mod 2^160. n is odd, hence
  invertible mod 2^160, so adding k*n to one challenge, with
  k = (H - sum e_j*) * n^-1 mod 2^160, hits the hash exactly without moving any
  challenge's residue mod n.

  With t_j drawn at random, every e_j* is a full-width residue mod n. Here
  every branch but the last instead fixes an in-range challenge e_j first and
  sets t_j = -e_j * d_j mod n, so that e_j* = e_j. The forged proof then has
  exactly ONE bad challenge, the last, at about |n| + 160 bits: a single
  oversized challenge is enough, and the range check has to hold for each
  challenge, not for the set.

  `witness` is v, the n-th root of the ciphertext's blinding factor.
  """
  from helios.crypto import paillier as P

  pk = ciphertext.pk
  n, n2 = pk.n, pk.n2
  L = len(plaintexts)

  d = []
  for j, plaintext in enumerate(plaintexts):
    d.append((true_m - plaintext.m) % n)
    if d[j] == 0:
      raise ValueError('branch %d is true; this recipe forges false branches' % j)

  s = [P.random_z_star_n(n) for _ in range(L)]
  e = [P.random_lt(P.CHALLENGE_MODULUS) for _ in range(L - 1)]
  t = [(-e[j] * d[j]) % n for j in range(L - 1)] + [P.random_lt(n)]
  a = [(pow(s[j], n, n2) * (1 + t[j] * n)) % n2 for j in range(L)]
  H = challenge_generator(a)

  e_last = (-t[-1] * pow(d[-1], -1, n)) % n
  k = ((H - sum(e) - e_last) * pow(n, -1, P.CHALLENGE_MODULUS)) \
      % P.CHALLENGE_MODULUS
  e.append(e_last + k * n)

  z = [(s[j] * pow(witness, e[j], n)) % n for j in range(L)]
  return P.PaillierZKDisjunctiveProof(
    [P.PaillierZKProof(a[j], e[j], z[j]) for j in range(L)])


def _audit_disjunctive_proof(ciphertext, plaintexts, proof, challenge_generator):
  """
  Each check the disjunctive verifier makes, evaluated separately.

  A test that feeds the verifier a bad proof proves something only if the proof
  is bad in exactly ONE way: a forgery that also broke a second check would be
  rejected whether or not the check under test exists, and the test would pass
  vacuously. The tests below use this to pin down which check does the work.
  """
  from helios.crypto.paillier import CHALLENGE_MODULUS

  pk = ciphertext.pk
  n, n2 = pk.n, pk.n2

  equations, units = [], []
  for plaintext, p in zip(plaintexts, proof.proofs):
    u = ciphertext._statement_for(plaintext)
    equations.append(pow(p.response, n, n2)
                     == (p.commitment * pow(u, p.challenge, n2)) % n2)
    units.append(all(math.gcd(x, n) == 1 for x in (p.response, u, p.commitment)))

  commitments = [p.commitment for p in proof.proofs]
  return {
    'branch_count': len(plaintexts) == len(proof.proofs),
    'equations': all(equations),
    'units': all(units),
    'sum_matches_hash': (challenge_generator(commitments)
                         == sum(p.challenge for p in proof.proofs)
                         % CHALLENGE_MODULUS),
    'challenges_in_range': all(0 <= p.challenge < CHALLENGE_MODULUS
                               for p in proof.proofs),
  }


# What _audit_disjunctive_proof reports for a proof bad in exactly one way.
_FAILS_ONLY_THE_RANGE_CHECK = {
  'branch_count': True, 'equations': True, 'units': True,
  'sum_matches_hash': True, 'challenges_in_range': False}
_FAILS_ONLY_THE_UNIT_CHECK = {
  'branch_count': True, 'equations': True, 'units': False,
  'sum_matches_hash': True, 'challenges_in_range': True}


# The ishaq canary under DJN §4.1 (the per-mode Python canary, and the JS
# canary tests 11 and 11d): proofs per run, and the band the above-n/2 count
# of each group must fall in. Half of all honest responses lie above n/2, so an
# honest group of 32 leaves [4, 28] with probability ~1e-5.
CANARY_TRIALS = 32
CANARY_MIN_ABOVE_HALF = 4


def _canary_verdict(real, simulated, n):
  """The measurements check_response_distribution.js reports, in Python."""
  real_bits = [z.bit_length() for z in real]
  simulated_bits = [z.bit_length() for z in simulated]
  return {
    'trials': len(real),
    'real_bits': real_bits,
    'simulated_bits': simulated_bits,
    'delta_bits': abs(statistics.mean(real_bits)
                      - statistics.mean(simulated_bits)),
    'real_above_half': sum(1 for z in real if z > n // 2),
    'simulated_above_half': sum(1 for z in simulated if z > n // 2),
  }


def _canary_alarms(verdict):
  """
  Every criterion of the ishaq canary that `verdict` trips. Empty means the
  real and simulated responses are indistinguishable by all it measures.

  - Mean bit lengths within 5 bits (see test 11's JS variant for why 5), and
    bit-length distributions that pass a two-sample KS test at 1%. These catch
    a response drawn from a short range, and ishaq's mod-n^2 reduction.
  - In each group, between CANARY_MIN_ABOVE_HALF and trials minus that many
    responses above n/2. A response drawn from a 'long' exponent range,
    [0, n/2), never gets there, yet is only one bit shorter than an honest
    one -- within noise of both bit-length criteria. Test 11d shows this is
    the criterion that catches it.
  """
  alarms = []
  if verdict['delta_bits'] >= 5.0:
    alarms.append('mean bit lengths differ by %.1f bits' % verdict['delta_bits'])

  d, d_crit = _two_sample_ks(verdict['real_bits'], verdict['simulated_bits'])
  if d >= d_crit:
    alarms.append('bit-length KS statistic %.3f >= %.3f' % (d, d_crit))

  trials = verdict['trials']
  for group in ('real', 'simulated'):
    above = verdict[group + '_above_half']
    if not CANARY_MIN_ABOVE_HALF <= above <= trials - CANARY_MIN_ABOVE_HALF:
      alarms.append('%d of %d %s responses above n/2' % (above, trials, group))

  return alarms


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

  def test_12f_oversized_challenge_forgery_is_rejected(self):
    """
    DJN §5.2 makes every branch challenge "a random t bit number". A verifier
    that checks only that the challenges SUM to the hash mod 2^160 accepts one
    challenge of about |n| + 160 bits, and that is enough to prove a ciphertext
    encrypts a plaintext it does not -- see _forge_oversized_challenge_proof.
    Before the range check existed, this verified Enc(2), Enc(-5) and a
    13-selection sum on a max-12 question at 2048 bits.

    The key is 1024 bits rather than the class's medium key so that
    2^160 < min(p, q). That is the regime in which Pi_root is sound at all, so
    a forgery here is a real soundness break rather than a toy-size artifact.
    """
    P = self.paillier
    kp = P.Paillier(key_size=512).generate_keypair()
    pk = kp.pk

    def enc_2():
      c, r = pk.encrypt_return_r(P.PaillierPlaintext(2, pk))
      return c, r, 2, pk.generate_plaintexts(0, 1)

    def thirteen_selections():
      # the homomorphic sum a ballot selecting 13 of 20 candidates produces
      C, R = 0, pk.randomness_identity
      for i in range(20):
        c, r = pk.encrypt_return_r(P.PaillierPlaintext(1 if i < 13 else 0, pk))
        C = c * C
        R = pk.combine_randomness(R, r)
      return C, R, 13, pk.generate_plaintexts(0, 12)

    for label, build in (('Enc(2) over {0, 1}', enc_2),
                         ('Enc(13) over 0..12', thirteen_selections)):
      with self.subTest(label):
        c, randomness, true_m, plaintexts = build()
        self.assertEqual(kp.sk.decryption_factor(c), true_m)
        witness = pk.proof_witness(randomness)

        oversized = _forge_oversized_challenge_proof(
          c, plaintexts, true_m, witness, self.gen)

        # The same forgery with the big challenge pushed below zero: its
        # residues mod n and mod 2^160 are unchanged, so it forges just as
        # well. This guards the lower half of the range check.
        negative = P.PaillierZKDisjunctiveProof(
          [P.PaillierZKProof(p.commitment, p.challenge, p.response)
           for p in oversized.proofs])
        last, shift = negative.proofs[-1], pk.n * P.CHALLENGE_MODULUS
        last.challenge -= shift
        last.response = (last.response * pow(witness, -shift, pk.n)) % pk.n
        self.assertLess(last.challenge, 0)

        for variant, proof in (('oversized', oversized), ('negative', negative)):
          # The forgery must be real -- it passes every check except the
          # range check -- or this test would pass whatever the verifier did.
          self.assertEqual(
            _audit_disjunctive_proof(c, plaintexts, proof, self.gen),
            _FAILS_ONLY_THE_RANGE_CHECK,
            f'{label}, {variant}: not a forgery that isolates the range check')

          # ...and only the last challenge is out of range, so each variant
          # tests one bound of the check alone.
          self.assertEqual(
            [0 <= p.challenge < P.CHALLENGE_MODULUS for p in proof.proofs],
            [True] * (len(plaintexts) - 1) + [False])

          self.assertFalse(
            c.verify_disjunctive_encryption_proof(plaintexts, proof, self.gen),
            f'{label}, {variant} challenge: a forged proof verified, so the '
            f'verifier is not checking that each challenge is in [0, 2^160)')

  def test_12g_values_sharing_a_factor_with_n_are_rejected(self):
    """
    DJN §5.2 requires "u, a, z are prime to n". PaillierZKProof.verify checks
    it, but until this test nothing exercised the check, so deleting it would
    have failed nothing. Both proofs below pass every other check the verifier
    makes, so the unit checks alone stand between them and acceptance.
    """
    P = self.paillier
    pk, n, n2 = self.pk, self.pk.n, self.pk.n2

    # --- the all-zeros proof ------------------------------------------------
    # With a = z = 0 the equation reads 0 = 0 for any statement and any
    # challenge, leaving only the challenge sum to satisfy. Against a
    # ciphertext of 2, this "proves" that 2 is a bit.
    c, _ = self._encrypt(2)
    H = self.gen([0, 0])
    e0 = P.random_lt(P.CHALLENGE_MODULUS)
    zeros = P.PaillierZKDisjunctiveProof([
      P.PaillierZKProof(0, e0, 0),
      P.PaillierZKProof(0, (H - e0) % P.CHALLENGE_MODULUS, 0)])

    self.assertEqual(_audit_disjunctive_proof(c, self.bits, zeros, self.gen),
                     _FAILS_ONLY_THE_UNIT_CHECK)
    self.assertFalse(
      c.verify_disjunctive_encryption_proof(self.bits, zeros, self.gen),
      'the all-zeros proof verified: a ciphertext of 2 passed as a bit')

    # --- a response that is a multiple of p ---------------------------------
    # An honest proof for a ciphertext of 1, except that the simulated branch
    # draws its response as a multiple of p and solves for its commitment as
    # usual. Every equation holds and the challenges sum to the hash; only z
    # (and with it a) now shares the factor p with n.
    c, r = self._encrypt(1)
    p = self.sk.p

    u0 = c._statement_for(self.bits[0])
    e0 = P.random_lt(P.CHALLENGE_MODULUS)
    z0 = (p * P.random_z_star_n(n)) % n
    a0 = (pow(z0, n, n2) * pow(pow(u0, e0, n2), -1, n2)) % n2

    s = P.random_z_star_n(n)
    a1 = pow(s, n, n2)
    e1 = (self.gen([a0, a1]) - e0) % P.CHALLENGE_MODULUS
    z1 = (s * pow(pk.proof_witness(r), e1, n)) % n

    shared = P.PaillierZKDisjunctiveProof([
      P.PaillierZKProof(a0, e0, z0), P.PaillierZKProof(a1, e1, z1)])

    self.assertEqual(math.gcd(z0, n), p)
    self.assertEqual(_audit_disjunctive_proof(c, self.bits, shared, self.gen),
                     _FAILS_ONLY_THE_UNIT_CHECK)
    self.assertFalse(
      c.verify_disjunctive_encryption_proof(self.bits, shared, self.gen),
      'a proof whose response shares the factor p with n verified')

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
    for mode in ('short', 'long'):
      self.assertEqual(
        djn_keypair(mode).pk.randomness_identity, 0,
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


class SafePrimeGeneratorTests(unittest.TestCase):
  """
  generate_safe_prime, the sieved search behind DJN §4.1 key generation.

  Its contract: an int p of exactly `bits` bits, at least
  min_p = isqrt(2^(2*bits - 1)) + 1 -- the sqrt(2) bound -- with p = 2p'+1 and
  both p and p' prime. Checked at sizes where safe primes are cheap; the full
  1024-bit size is PaillierKeyGenerationTests' slow test.
  """

  # Samples per size. Fewer at 512 bits, where one takes a couple of seconds.
  SAMPLES = {64: 20, 128: 20, 256: 20, 512: 3}

  @classmethod
  def setUpClass(cls):
    from helios.crypto import paillier
    cls.paillier = paillier
    cls.samples = {bits: [paillier.generate_safe_prime(bits)
                          for _ in range(count)]
                   for bits, count in cls.SAMPLES.items()}

  def test_every_sample_meets_the_contract(self):
    from Crypto.Util import number

    for bits, samples in self.samples.items():
      min_p = math.isqrt(1 << (2 * bits - 1)) + 1
      for p in samples:
        with self.subTest(bits=bits, p=p):
          self.assertIs(type(p), int)
          self.assertEqual(p.bit_length(), bits)
          self.assertGreaterEqual(p, min_p)
          self.assertEqual(p % 4, 3)
          self.assertTrue(number.isPrime(p))
          self.assertTrue(number.isPrime((p - 1) // 2), 'not a safe prime')

  def test_two_samples_meet_the_djn41_conditions(self):
    for bits, samples in self.samples.items():
      with self.subTest(bits=bits):
        p, q = samples[0], next(s for s in samples if s != samples[0])
        self.paillier.check_djn41_primes(p, q)   # must not raise

  def test_every_product_has_exactly_twice_the_bits(self):
    """
    The 2047-bit regression: without the sqrt(2) bound, the product of two
    bits-bit safe primes is one bit short ~39% of the time (2 ln 2 - 1), and
    the full-size key generation test once drew a 2047-bit n that way.
    """
    samples = self.samples[256]
    pairs = [(p, q) for i, p in enumerate(samples) for q in samples[i + 1:]]
    self.assertGreaterEqual(len(pairs), 50)

    for p, q in pairs:
      self.assertEqual((p * q).bit_length(), 512)

  def test_calls_return_different_primes(self):
    self.assertNotEqual(self.paillier.generate_safe_prime(128),
                        self.paillier.generate_safe_prime(128))
    for bits, samples in self.samples.items():
      self.assertEqual(len(set(samples)), len(samples), f'repeats at {bits}')

  def test_the_sieve(self):
    """
    The product M holds exactly the odd primes up to the bound: odd, divisible
    by every one of them, and they are all the odd primes there are.
    """
    from Crypto.Util import number

    P = self.paillier
    self.assertEqual(P._SIEVE_PRODUCT % 2, 1)
    for q in P._SIEVE_PRIMES:
      self.assertEqual(P._SIEVE_PRODUCT % q, 0, q)
    self.assertEqual(
      list(P._SIEVE_PRIMES),
      [c for c in range(3, P._SIEVE_BOUND + 1, 2) if number.isPrime(c)])

  def test_a_size_below_the_sieve_is_refused(self):
    """
    Every safe prime at such a size would have p' among the sieve primes and
    be rejected, so the search would never end. It refuses instead.
    """
    with self.assertRaises(ValueError):
      self.paillier.generate_safe_prime(8)


class DJN41KeyTests(unittest.TestCase):
  """
  DJN §4.1 at the level of the key: what §4.1 asks of p and q, how a key records
  its mode, the retired key format, and the JavaScript ishaq canary across all
  three modes. Per-mode behaviour is in DJN41ShortTests and DJN41LongTests.
  """

  def setUp(self):
    from helios.crypto import paillier
    self.paillier = paillier

  def test_the_fixed_primes_meet_the_djn41_conditions(self):
    from Crypto.Util import number

    self.assertEqual((DJN_P * DJN_Q).bit_length(), 1024)
    for prime in (DJN_P, DJN_Q):
      self.assertEqual(prime.bit_length(), 512)
      self.assertEqual(prime % 4, 3)
      self.assertTrue(number.isPrime(prime))
      self.assertTrue(number.isPrime((prime - 1) // 2), 'not a safe prime')
    self.assertEqual(math.gcd(DJN_P - 1, DJN_Q - 1), 2)

    self.paillier.check_djn41_primes(DJN_P, DJN_Q)   # must not raise

  def test_from_primes_refuses_primes_that_are_not_safe(self):
    """
    Ordinary primes serve standard Paillier and not §4.1. Each pair below is
    refused in both DJN modes, and by the check it breaks -- asserted by
    message.
    """
    from Crypto.Util import number

    P = self.paillier

    # a 512-bit prime that is 3 mod 4 but not safe: it breaks nothing else
    while True:
      ordinary = number.getPrime(512)
      if ordinary % 4 == 3 and not number.isPrime((ordinary - 1) // 2):
        break

    cases = [
      ('the medium test primes', MEDIUM_P, MEDIUM_Q, 'not a safe prime'),
      ('one safe prime, one not', DJN_P, ordinary, 'q is not a safe prime'),
      ('p = 1 mod 4', 1000033, DJN_Q, '3 mod 4'),
      ('p composite, (p-1)/2 prime', 15, DJN_Q, 'p is not prime'),
      ('p = q', DJN_P, DJN_P, 'distinct'),
    ]
    for mode in ('short', 'long'):
      for label, p, q, message in cases:
        with self.subTest(mode=mode, case=label):
          with self.assertRaisesRegex(ValueError, message):
            P.PaillierKeyPair.from_primes(p, q, djn41_mode=mode)

    # ...while standard Paillier still takes ordinary primes
    kp = P.PaillierKeyPair.from_primes(DJN_P, ordinary)
    self.assertFalse(kp.pk.uses_djn_41)

  def test_unknown_modes_are_refused(self):
    P = self.paillier
    for mode in ('on', 'medium', True, None):
      with self.subTest(mode=mode):
        with self.assertRaises(ValueError):
          P.Paillier(djn41_mode=mode)
        with self.assertRaises(ValueError):
          P.PaillierKeyPair.from_primes(DJN_P, DJN_Q, djn41_mode=mode)

  def test_the_model_offers_exactly_the_crypto_modes(self):
    from helios.models import Election

    self.assertEqual([mode for mode, _ in Election.PAILLIER_DJN41_MODES],
                     list(self.paillier.DJN41_MODES))

  def test_standard_key_serializes_as_exactly_n_and_g(self):
    """
    A standard key must NOT gain null h/hn/djn41_mode fields. Stored elections
    and the B8 ballot-size canary both depend on this -- including for a
    standard key that happens to sit on safe primes.
    """
    pk = djn_keypair('off').pk
    self.assertIsNone(pk.h)
    self.assertIsNone(pk.hn)
    self.assertEqual(set(pk.to_dict()), {'n', 'g'})

    for hint in ('paillier/PublicKey', 'legacy/EGPublicKey'):
      with self.subTest(hint=hint):
        serialized = datatypes.LDObject.instantiate(pk, datatype=hint).toDict()
        self.assertEqual(serialized, {'n': str(pk.n), 'g': str(pk.g)})

        back = datatypes.LDObject.fromDict(serialized, type_hint=hint).wrapped_obj
        self.assertEqual(back.djn41_mode, 'off')
        self.assertIsNone(back.h)
        self.assertEqual(back, pk)

  def test_the_retired_key_format_is_refused(self):
    """
    The construction this replaced serialized as {n, g, h, g_prime}, with no
    mode. Read as a standard key it would quietly run an election labelled
    'short' as 'off', so every loader refuses it.
    """
    P = self.paillier
    pk = djn_keypair('short').pk
    retired = {'n': str(pk.n), 'g': str(pk.g), 'h': str(pk.hn), 'g_prime': '5'}

    with self.assertRaisesRegex(Exception, 'retired'):
      P.PaillierPublicKey.from_dict(retired)

    for hint in ('paillier/PublicKey', 'legacy/EGPublicKey'):
      with self.subTest(hint=hint):
        with self.assertRaisesRegex(Exception, 'retired'):
          datatypes.LDObject.fromDict(retired, type_hint=hint)

  # --- test 11, the JavaScript ishaq canary, in every mode -----------------

  def test_11_javascript_response_distribution_all_modes(self):
    """
    Test 11 (the ishaq canary) on the JAVASCRIPT side, in all three modes.

    This is the test whose absence let a real ballot-secrecy bug ship. Test 11
    existed only in Python, and Python was correct; the booth's
    Paillier.Proof.generate/simulate drew their randomness from
    pk.randomRandomness(), which DJN §4.1 redefines from "uniform on Z*_n" to
    an exponent from a narrower range. Simulated branches came out ~510 bits
    against the real branch's ~2045, so the voter's selection was readable off
    the ballot.

    Every proof still verified and cross-language agreement still passed. Only
    a 12% shift in ballot size gave it away.

    Every mode runs on the fixed safe primes' 1024-bit n, which the modulus
    must stay well clear of what each comparison measures: a 'short' exponent
    is 512 bits there, so the bug would put simulated responses ~512 bits
    below real ones. A 'long' exponent is one bit narrower than n, which bit
    length cannot see -- hence the above-n/2 count (see _canary_alarms, and
    test 11d for proof that it is needed).
    """
    import shutil

    if not shutil.which('node'):
      self.skipTest('node not available')

    for mode in self.paillier.DJN41_MODES:
      with self.subTest(djn41_mode=mode):
        verdict = _run_node_bridge(self, 'check_response_distribution.js',
                                   djn_keypair(mode).pk.to_dict(),
                                   str(CANARY_TRIALS))

        self.assertEqual(verdict['djn41_mode'], mode,
                         'the booth parsed the key in a different mode')
        self.assertTrue(verdict['all_verified'])
        self.assertEqual(
          [], _canary_alarms(verdict),
          f'JS real and simulated responses are distinguishable under '
          f'{mode!r}, so the real branch -- the vote -- can be read off the '
          f'ballot. Check that Proof.generate and Proof.simulate use '
          f'randomZStarN(), not randomRandomness().')

  def test_11d_javascript_canary_catches_the_historic_bug(self):
    """
    Guards the guard, as test 11b does for Python. The historic booth bug is
    put back -- proofs drawing from randomRandomness() -- and the canary must
    raise the alarm in both DJN modes. Under 'long' only the above-n/2 count
    can: by bit length the two groups sit within a bit of each other.
    """
    import shutil

    if not shutil.which('node'):
      self.skipTest('node not available')

    for mode in ('short', 'long'):
      with self.subTest(djn41_mode=mode):
        verdict = _run_node_bridge(self, 'check_response_distribution.js',
                                   djn_keypair(mode).pk.to_dict(), '16',
                                   '--reintroduce-bug')

        self.assertTrue(verdict['all_verified'],
                        'the bug is invisible to verification -- the point')

        alarms = _canary_alarms(verdict)
        self.assertIn('0 of 16 simulated responses above n/2', alarms)

        if mode == 'short':
          self.assertGreater(verdict['delta_bits'], 100)
        else:
          self.assertLess(verdict['delta_bits'], 5.0,
                          'expected bit length alone to miss the long-mode bug')


class _DJN41ModeTests:
  """
  DJN §4.1 behaviour, run once per mode by DJN41ShortTests and DJN41LongTests.

  Every test uses the fixed safe primes (|n| = 1024), so the suite never waits
  on safe-prime generation; PaillierKeyGenerationTests keeps the one full-size
  key generation.
  """

  MODE = None

  def setUp(self):
    from helios.crypto import paillier
    self.paillier = paillier
    self.gen = paillier.paillier_disjunctive_challenge_generator
    self.kp = djn_keypair(self.MODE)
    self.pk, self.sk = self.kp.pk, self.kp.sk
    self.bits = self.pk.generate_plaintexts(0, 1)

  def _encrypt(self, m):
    return self.pk.encrypt_return_r(self.paillier.PaillierPlaintext(m, self.pk))

  def _sum_of(self, votes):
    """The homomorphic sum of Enc(v) over `votes`, and its combined randomness."""
    C, R = 0, self.pk.randomness_identity
    for v in votes:
      c, r = self._encrypt(v)
      C = c * C
      R = self.pk.combine_randomness(R, r)
    return C, R

  # --- the key ------------------------------------------------------------

  def test_the_key_carries_its_mode(self):
    self.assertEqual(self.pk.djn41_mode, self.MODE)
    self.assertTrue(self.pk.uses_djn_41)

  def test_hn_is_h_to_the_n(self):
    pk = self.pk
    self.assertTrue(0 < pk.h < pk.n)
    self.assertEqual(math.gcd(pk.h, pk.n), 1)
    self.assertEqual(pk.hn, pow(pk.h, pk.n, pk.n2))

  def test_h_is_minus_a_square(self):
    """
    DJN's base is h = -x^2 mod n, not a square. With p = q = 3 (mod 4), -1 is a
    non-residue mod both primes, so h is a non-residue mod p and mod q while -h
    is a residue mod both. The construction this replaced used a square, g'^2,
    and fails the second assertion.
    """
    for prime in (self.sk.p, self.sk.q):
      def legendre(a):
        return pow(a % prime, (prime - 1) // 2, prime)

      self.assertEqual(legendre(-self.pk.h), 1, '-h is not a square')
      self.assertEqual(legendre(self.pk.h), prime - 1, 'h is a square')

  def test_validation_checks_each_djn41_parameter(self):
    """
    validate_pk_params in a DJN mode: 0 < h < n, gcd(h, n) = 1,
    hn = h^n mod n^2, and a mode in {short, long}. Each forgery below breaks
    exactly one of those and must be refused by THAT check, asserted by
    message, so that a rejection for some other reason cannot stand in for it.
    """
    P = self.paillier
    pk, p = self.pk, self.sk.p
    n, n2 = pk.n, pk.n2

    def forged(**changes):
      fields = dict(n=n, g=n + 1, h=pk.h, hn=pk.hn, djn41_mode=self.MODE)
      fields.update(changes)
      return P.PaillierPublicKey(**fields)

    cases = [
      ('forged hn', forged(hn=pk.hn * pk.hn % n2), r'hn != h\^n'),
      # consistent hn, so only the unit check can object
      ('h sharing a factor with n', forged(h=p, hn=pow(p, n, n2)),
       'not a unit'),
      # (h+n)^n = h^n mod n^2, so hn stays consistent here too
      ('h out of range', forged(h=pk.h + n), 'out of range'),
      ('a mode that is not short or long', forged(djn41_mode='medium'),
       'djn41_mode must be'),
      ('a standard key carrying h', forged(djn41_mode='off'),
       'must not carry them'),
      ('missing hn', forged(hn=None), 'must carry h and hn'),
    ]

    with _validation_floor(1024):
      pk.validate_pk_params()   # the genuine key passes

      for label, key, message in cases:
        with self.subTest(label):
          with self.assertRaisesRegex(Exception, message):
            key.validate_pk_params()

    # outside the lowered floor, the length check still comes first
    with self.assertRaisesRegex(Exception, 'insufficient length'):
      pk.validate_pk_params()

  # --- exponents ------------------------------------------------------------

  def test_exponents_come_from_the_modes_range(self):
    """
    'short': [0, 2^ceil(|n|/2)); 'long': [0, n // 2). Checked from both sides:
    no draw reaches the bound, AND the draws reach the top half of the range --
    a regression to a narrower range, such as the old fixed 512 bits, would
    pass the first check and fail the second. encrypt_return_r's r is checked
    too: it must draw through random_randomness.
    """
    pk = self.pk
    expected = {'short': 1 << 512, 'long': pk.n // 2}[self.MODE]
    self.assertEqual(pk.exponent_bound, expected)

    draws = [pk.random_randomness() for _ in range(40)]
    draws += [self._encrypt(1)[1] for _ in range(8)]

    for r in draws:
      self.assertTrue(0 <= r < expected, r)
    self.assertGreaterEqual(max(draws), expected // 2,
                            'no draw reached the top half of the range')

  # --- fixed-base tables ------------------------------------------------------

  def test_tables_agree_with_pow(self):
    """
    hn^a mod n^2 and h^a mod n from the tables must equal pow() exactly: for
    single exponents, for 0, for a sum of 222 exponents -- a question's
    combined randomness, longer than any one exponent -- and, through the
    fallback, for an exponent longer than the tables.
    """
    P = self.paillier
    pk = self.pk
    T_hn, T_h = pk.fixed_base_tables()
    self.assertEqual(len(T_hn),
                     pk.exponent_bound.bit_length() + P.TABLE_HEADROOM_BITS)

    total = sum(pk.random_randomness() for _ in range(222))
    self.assertGreater(total.bit_length(), pk.exponent_bound.bit_length())

    exponents = [0, 1, 2, pk.exponent_bound - 1, total]
    exponents += [pk.random_randomness() for _ in range(6)]
    for e in exponents:
      # base=None: pow(None, ...) would raise, so a match proves the table
      # path produced it
      self.assertEqual(P._fixed_base_pow(None, T_hn, e, pk.n2),
                       pow(pk.hn, e, pk.n2))
      self.assertEqual(P._fixed_base_pow(None, T_h, e, pk.n),
                       pow(pk.h, e, pk.n))

      # and the two methods encryption and the witness call
      self.assertEqual(pk._hn_pow(e), pow(pk.hn, e, pk.n2))
      self.assertEqual(pk._h_pow(e), pow(pk.h, e, pk.n))

    too_long = 1 << len(T_h)
    self.assertEqual(pk._hn_pow(too_long), pow(pk.hn, too_long, pk.n2))
    self.assertEqual(pk._h_pow(too_long), pow(pk.h, too_long, pk.n))

  def test_tables_are_built_once_and_rebuilt_for_a_new_base(self):
    pk = self.pk
    first = pk.fixed_base_tables()
    self.assertIs(pk.fixed_base_tables()[0], first[0],
                  'the tables were rebuilt on a second use')

    # a key whose base is replaced must not go on using the old tables
    other = djn_keypair(self.MODE).pk
    pk.h, pk.hn = other.h, other.hn
    self.assertIsNot(pk.fixed_base_tables()[0], first[0])
    self.assertEqual(pk._h_pow(12345), pow(other.h, 12345, pk.n))

  # --- the witness -------------------------------------------------------------

  def test_the_witness_is_a_real_nth_root(self):
    """
    witness^n = hn^a (mod n^2), for one exponent and for combined randomness.
    The property the whole mode rests on: without it Pi_root has no witness
    and every ballot proof is unprovable.
    """
    pk = self.pk
    exponents = [pk.random_randomness() for _ in range(5)]
    exponents.append(sum(exponents))

    for a in exponents:
      witness = pk.proof_witness(a)
      self.assertEqual(pow(witness, pk.n, pk.n2), pow(pk.hn, a, pk.n2))
      self.assertEqual(math.gcd(witness, pk.n), 1, 'witness must be in Z*_n')

  # --- correctness ---------------------------------------------------------------

  def test_encryption_is_djn41s_function(self):
    """c = (1 + m*n) * hn^a mod n^2, exactly."""
    pk = self.pk
    c, a = self._encrypt(7)
    self.assertEqual(c.c, (1 + 7 * pk.n) * pow(pk.hn, a, pk.n2) % pk.n2)

  def test_decryption_with_and_without_crt(self):
    for m in (0, 1, 2, 12, 10 ** 6, self.pk.n - 1):
      c, _ = self._encrypt(m)
      self.assertEqual(self.sk.decryption_factor(c), m, f'CRT path, m={m}')
      self.assertEqual(self.sk.decrypt_no_crt(c), m, f'non-CRT path, m={m}')

  def test_homomorphic_addition(self):
    C, R = self._sum_of([1, 0, 1, 1, 0, 1])
    self.assertEqual(self.sk.decryption_factor(C), 4)

    # exponents ADD: the product is Enc(4) under the combined randomness
    self.assertEqual(self.pk.randomness_identity, 0)
    self.assertEqual(
      C.c, self.pk.encrypt_with_r(self.paillier.PaillierPlaintext(4, self.pk),
                                  R).c)

  # --- ballot proofs -------------------------------------------------------------

  def test_ballot_proofs_verify(self):
    for bit in (0, 1):
      c, r = self._encrypt(bit)
      proof = c.generate_disjunctive_encryption_proof(self.bits, bit, r,
                                                      self.gen)
      self.assertTrue(
        c.verify_disjunctive_encryption_proof(self.bits, proof, self.gen))

  def test_the_naive_cheat_is_rejected(self):
    """A ciphertext of 2, honestly randomized, cannot be proven a bit."""
    c, r = self._encrypt(2)
    for claimed in (0, 1):
      proof = c.generate_disjunctive_encryption_proof(self.bits, claimed, r,
                                                      self.gen)
      self.assertFalse(
        c.verify_disjunctive_encryption_proof(self.bits, proof, self.gen))

  def test_the_oversized_challenge_forgery_is_rejected(self):
    """
    Test 12f's forgery in this mode. It needs only the n-th root of the
    ciphertext's blinding factor -- here the witness h^a mod n.
    """
    for true_m, max_sel in ((2, 1), (13, 12)):
      with self.subTest(true_m=true_m):
        plaintexts = self.pk.generate_plaintexts(0, max_sel)
        c, a = self._encrypt(true_m)
        forged = _forge_oversized_challenge_proof(
          c, plaintexts, true_m, self.pk.proof_witness(a), self.gen)

        self.assertEqual(
          _audit_disjunctive_proof(c, plaintexts, forged, self.gen),
          _FAILS_ONLY_THE_RANGE_CHECK)
        self.assertFalse(
          c.verify_disjunctive_encryption_proof(plaintexts, forged, self.gen))

  def test_overall_proof_with_combined_randomness(self):
    """
    Where the modes differ from standard Paillier: the overall proof's witness
    is h raised to the SUM of the exponents. A legal count verifies, and 13
    selections against max 12 do not.
    """
    sums = self.pk.generate_plaintexts(0, 12)

    C, R = self._sum_of([1] * 5 + [0] * 15)
    proof = C.generate_disjunctive_encryption_proof(sums, 5, R, self.gen)
    self.assertTrue(C.verify_disjunctive_encryption_proof(sums, proof, self.gen))
    self.assertEqual(self.sk.decryption_factor(C), 5)

    C, R = self._sum_of([1] * 13 + [0] * 7)
    proof = C.generate_disjunctive_encryption_proof(sums, 12, R, self.gen)
    self.assertFalse(C.verify_disjunctive_encryption_proof(sums, proof, self.gen))

  def test_decryption_proof_unchanged(self):
    """
    The trustee still recovers an n-th root as u^(n^-1 mod lambda): hn^a is an
    n-th power like any other, so §2.8 needs no change.
    """
    c, _ = self._encrypt(42)
    m, proof = self.sk.decryption_factor_and_proof(c)

    self.assertEqual(m, 42)
    self.assertTrue(self.pk.verify_decryption_proof(c, m, proof))
    self.assertFalse(self.pk.verify_decryption_proof(c, 41, proof))

  def test_python_response_distribution(self):
    """
    The ishaq canary in this mode, on the Python side: PaillierZKProof.generate
    and simulate must draw from Z*_n, never from random_randomness(). Same
    criteria as the JS canary (see _canary_alarms).
    """
    real, simulated = [], []
    for trial in range(2 * CANARY_TRIALS):
      real_index = trial % 2
      c, r = self._encrypt(real_index)
      proof = c.generate_disjunctive_encryption_proof(self.bits, real_index, r,
                                                      self.gen)
      for idx, p in enumerate(proof.proofs):
        (real if idx == real_index else simulated).append(p.response)

    verdict = _canary_verdict(real, simulated, self.pk.n)
    self.assertEqual([], _canary_alarms(verdict))

  # --- serialization ---------------------------------------------------------------

  def test_serialization_round_trips_in_this_mode(self):
    """
    {n, g, h, hn, djn41_mode}, through from_dict, the paillier/PublicKey
    datatype, the static 'legacy/EGPublicKey' hint a trustee key is stored
    under, and inside a secret key. What comes back is equal, in the same mode,
    and still encrypts correctly.
    """
    P = self.paillier
    pk = self.pk

    d = pk.to_dict()
    self.assertEqual(set(d), {'n', 'g', 'h', 'hn', 'djn41_mode'})
    self.assertEqual(d['djn41_mode'], self.MODE)

    with _validation_floor(1024):
      self.assertEqual(P.PaillierPublicKey.from_dict(d), pk)

    for hint in ('paillier/PublicKey', 'legacy/EGPublicKey'):
      with self.subTest(hint=hint):
        serialized = datatypes.LDObject.instantiate(pk, datatype=hint).toDict()
        self.assertEqual(serialized, d)

        back = datatypes.LDObject.fromDict(serialized, type_hint=hint).wrapped_obj
        self.assertIsInstance(back, P.PaillierPublicKey)
        self.assertEqual(back, pk)

        c, a = back.encrypt_return_r(P.PaillierPlaintext(3, back))
        self.assertLess(a, pk.exponent_bound)
        self.assertEqual(self.sk.decryption_factor(c), 3)

    sk_ld = datatypes.LDObject.instantiate(self.sk, datatype='paillier/SecretKey')
    sk_back = datatypes.LDObject.fromDict(
      sk_ld.toDict(), type_hint='paillier/SecretKey').wrapped_obj
    self.assertEqual(sk_back.public_key, pk)

  # --- test 9 in this mode ---------------------------------------------------------

  def test_cross_language_agreement(self):
    """
    Proofs built by the booth's JavaScript verify in Python, and Python's --
    including a forgery that must fail -- get the same verdicts in JS.

    A proof verifies whatever encryption function made its ciphertext, so
    agreement on proofs alone would pass even if the booth ignored the key's
    mode. So the booth also reports the mode it parsed and the randomness it
    used, and Python re-encrypts under that randomness: the ciphertexts must
    match exactly.
    """
    import shutil

    if not shutil.which('node'):
      self.skipTest('node not available')

    P = self.paillier
    pk = self.pk
    sums = pk.generate_plaintexts(0, 12)

    c, r = self._encrypt(1)
    individual = c.generate_disjunctive_encryption_proof(self.bits, 1, r,
                                                         self.gen)
    C, R = self._sum_of([1] * 5 + [0] * 15)
    overall = C.generate_disjunctive_encryption_proof(sums, 5, R, self.gen)
    fc, fa = self._encrypt(2)
    forged = _forge_oversized_challenge_proof(fc, self.bits, 2,
                                              pk.proof_witness(fa), self.gen)

    verdict = _run_node_bridge(self, 'crosscheck_proofs.js', {
      'public_key': pk.to_dict(),
      'cases': [
        {'label': 'python individual bit=1', 'ciphertext': c.to_dict(),
         'min': 0, 'max': 1, 'real_index': 1,
         'proof': individual.to_dict(), 'should_verify': True},
        {'label': 'python overall L=13, 5 selected', 'ciphertext': C.to_dict(),
         'min': 0, 'max': 12, 'real_index': 5,
         'proof': overall.to_dict(), 'should_verify': True},
        {'label': 'python forgery: Enc(2) as a bit', 'ciphertext': fc.to_dict(),
         'min': 0, 'max': 1, 'real_index': None,
         'proof': forged.to_dict(), 'should_verify': False},
      ],
      'generate': [
        {'label': 'js individual bit=1', 'kind': 'individual',
         'min': 0, 'max': 1, 'real_index': 1},
        {'label': 'js overall L=13, 5 selected', 'kind': 'overall',
         'min': 0, 'max': 12, 'selected': 5, 'n_slots': 20},
      ],
    })

    self.assertEqual(verdict['djn41_mode'], self.MODE,
                     'the booth parsed the key in a different mode')

    for v in verdict['verified']:
      self.assertTrue(v['ok'], f'JS disagreed with Python on "{v["label"]}": '
                               f'expected {v["expected"]}, got {v["got"]}')

    self.assertEqual(len(verdict['generated']), 2)
    for g in verdict['generated']:
      self.assertTrue(g['self_verifies'], g['label'])

      ct = P.PaillierCiphertext.from_dict(g['ciphertext'], pk)
      plaintexts = pk.generate_plaintexts(g['min'], g['max'])
      proof = P.PaillierZKDisjunctiveProof.from_dict(g['proof'])
      self.assertTrue(
        ct.verify_disjunctive_encryption_proof(plaintexts, proof, self.gen),
        f'Python rejected a JS-generated proof: {g["label"]}')

      # the booth encrypted with THIS mode's function, from its range
      a = int(g['randomness'])
      overall_sum = g['kind'] == 'overall'
      m = g['selected'] if overall_sum else g['min'] + g['real_index']
      self.assertLess(a, pk.exponent_bound * (20 if overall_sum else 1))
      self.assertEqual(
        pk.encrypt_with_r(P.PaillierPlaintext(m, pk), a).c, ct.c,
        f'{g["label"]}: JS and Python encrypt differently under the same '
        f'randomness')


class DJN41ShortTests(_DJN41ModeTests, unittest.TestCase):
  """DJN §4.1 with DJN's own exponent length: a ceil(|n|/2)-bit exponent."""
  MODE = 'short'


class DJN41LongTests(_DJN41ModeTests, unittest.TestCase):
  """DJN §4.1 with the exponent drawn from [0, n/2): DCR alone."""
  MODE = 'long'


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

  @tag('slow')
  def test_djn41_keygen_produces_a_valid_2048_bit_key_on_safe_primes(self):
    """
    The one full-size DJN §4.1 key generation in the suite, and deliberately
    slow: two 1024-bit safe primes, at a median of 12 s each with
    generate_safe_prime and a tail into tens of seconds. Tagged 'slow', so
    `--exclude-tag slow` skips it. Every other DJN test uses the fixed
    512-bit safe primes instead. 'short' and 'long' keys are generated
    identically, so one key serves both.
    """
    from Crypto.Util import number
    from helios.crypto import paillier

    kp = paillier.Paillier(key_size=1024, djn41_mode='short').generate_keypair()
    pk, sk = kp.pk, kp.sk

    self.assertEqual(number.size(pk.n), 2048)
    self.assertEqual(pk.djn41_mode, 'short')
    for prime in (sk.p, sk.q):
      self.assertEqual(number.size(prime), 1024)
      self.assertEqual(prime % 4, 3)
      self.assertTrue(number.isPrime((prime - 1) // 2), 'not a safe prime')
    self.assertEqual(math.gcd(sk.p - 1, sk.q - 1), 2)

    pk.validate_pk_params()   # full size: must not raise

    for mode, bound in (('short', 1 << 1024), ('long', pk.n // 2)):
      with self.subTest(mode=mode):
        pk.djn41_mode = mode
        self.assertEqual(pk.exponent_bound, bound)

        c, a = pk.encrypt_return_r(paillier.PaillierPlaintext(12345, pk))
        self.assertLess(a, bound)
        self.assertEqual(sk.decryption_factor(c), 12345)
        self.assertEqual(pow(pk.proof_witness(a), pk.n, pk.n2),
                         pow(pk.hn, a, pk.n2))

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

  def _forged_case(self, label, true_m, max_sel):
    """
    The oversized-challenge forgery (test 12f), built in Python for the JS
    verifier. It is checked to be real first -- every check but the challenge
    range passes -- or a JS rejection would prove nothing.
    """
    P = self.paillier
    plaintexts = self.pk.generate_plaintexts(0, max_sel)
    c, r = self.pk.encrypt_return_r(P.PaillierPlaintext(true_m, self.pk))
    proof = _forge_oversized_challenge_proof(
      c, plaintexts, true_m, self.pk.proof_witness(r), self.gen)

    self.assertEqual(_audit_disjunctive_proof(c, plaintexts, proof, self.gen),
                     _FAILS_ONLY_THE_RANGE_CHECK,
                     f'{label}: not a forgery that isolates the range check')

    return {'label': label, 'ciphertext': c.to_dict(), 'min': 0,
            'max': max_sel, 'real_index': None, 'proof': proof.to_dict(),
            'should_verify': False}

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
      self._forged_case('forged: Enc(2) as a bit, oversized challenge', 2, 1),
      self._forged_case('forged: 13 selections on max 12, oversized challenge',
                        13, 12),
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
    DJN §4.1 'off' -- standard Paillier is the thesis's main arm, and 'short'
    costs an extra assumption; CRT proofs on (it costs nothing). An existing
    election created before these columns existed must read the same way.
    """
    e = self._election('paillier', 'abl-default')
    self.assertEqual(e.paillier_djn41_mode, 'off')
    self.assertTrue(e.paillier_use_crt_proofs)

  def test_ablation_config_is_scheme_aware(self):
    self.assertEqual(self._election('elgamal', 'abl-eg').ablation_config, {},
                     'ElGamal has no Paillier ablations to report')

    pa = self._election('paillier', 'abl-pa')
    for mode in ('off', 'short', 'long'):
      pa.paillier_djn41_mode = mode
      self.assertEqual(pa.ablation_config,
                       {'paillier_djn41_mode': mode,
                        'paillier_use_crt_proofs': True})

  def test_crypto_params_follow_the_election_not_a_global(self):
    """
    The switch is per election. A module-level setting could not be varied
    cell by cell, could not be recovered from a stored election, and could be
    set on the wrong process entirely.

    In the DJN modes the trustee key is generated from 256-bit safe primes:
    full-size ones take minutes, and PaillierKeyGenerationTests covers them.
    """
    from unittest import mock

    from helios import views
    from helios.views import crypto_params_for

    for mode in ('off', 'short', 'long'):
      with self.subTest(mode=mode):
        e = self._election('paillier', f'abl-{mode}')
        e.paillier_djn41_mode = mode
        self.assertEqual(crypto_params_for(e).djn41_mode, mode)

        # ...and the generated key, read back from the database, carries it
        key_size = 1024 if mode == 'off' else 256
        with mock.patch.object(views.PAILLIER_PARAMS, 'key_size', key_size):
          e.generate_trustee(crypto_params_for(e))
        self.assertEqual(e.get_helios_trustee().public_key.djn41_mode, mode)

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
      'paillier_djn41_mode': 'long', 'paillier_use_crt_proofs': '0'})
    self.assertTrue(form.is_valid(), form.errors)
    self.assertEqual(form.cleaned_data['paillier_djn41_mode'], 'long')
    self.assertFalse(form.cleaned_data['paillier_use_crt_proofs'])

  def test_djn41_mode_accepts_exactly_the_three_modes(self):
    """
    The mode is a three-way choice, validated as one. Absent or empty means
    'off'. Anything else -- every spelling the old boolean accepted included --
    is a validation error rather than a guess, because a guessed mode is how an
    ablation cell ends up recording a configuration it never ran.
    """
    from helios.forms import ElectionForm

    base = {'short_name': 'x', 'name': 'X', 'description': '',
            'election_type': 'election', 'crypto_scheme': 'paillier'}

    for mode in ('off', 'short', 'long'):
      form = ElectionForm(data={**base, 'paillier_djn41_mode': mode})
      self.assertTrue(form.is_valid(), form.errors)
      self.assertEqual(form.cleaned_data['paillier_djn41_mode'], mode)

    for data in (base, {**base, 'paillier_djn41_mode': ''}):
      form = ElectionForm(data=data)
      self.assertTrue(form.is_valid(), form.errors)
      self.assertEqual(form.cleaned_data['paillier_djn41_mode'], 'off')

    for spelling in ('1', '0', 'true', 'on', 'Short', 'djn41'):
      form = ElectionForm(data={**base, 'paillier_djn41_mode': spelling})
      self.assertFalse(form.is_valid(), f'{spelling!r} was accepted as a mode')
      self.assertIn('paillier_djn41_mode', form.errors)

  def test_the_retired_boolean_is_refused_by_name(self):
    """
    A caller still posting paillier_use_djn41 -- the workload harness, until it
    learns the new field -- must fail loudly. Ignored, it would get 'off' while
    believing it had asked for DJN §4.1.
    """
    from helios.forms import ElectionForm

    base = {'short_name': 'x', 'name': 'X', 'description': '',
            'election_type': 'election', 'crypto_scheme': 'paillier'}

    for value in ('1', '0'):
      form = ElectionForm(data={**base, 'paillier_use_djn41': value})
      self.assertFalse(form.is_valid())
      self.assertIn('paillier_djn41_mode', ' '.join(form.non_field_errors()))

  def test_ablation_flags_parse_every_falsey_spelling(self):
    """
    Regression: posting '0' to turn a flag OFF used to turn it ON.

    forms.BooleanField uses CheckboxInput, whose value_from_datadict recognises
    only the literal strings "true"/"false" and otherwise returns bool(value) --
    and bool('0') is True. So an ablation cell asking for djn41=False created an
    election with djn41=True, while stamping False on its own records.

    The form reported valid, the election ran, the tally was correct, and the
    only symptom was that the A and B cells produced identical numbers.

    The §4.1 setting has since become a three-way choice (tested above); the
    CRT flag is still a boolean parsed from the raw post.
    """
    from helios.forms import ElectionForm

    base = {'short_name': 'x', 'name': 'X', 'description': '',
            'election_type': 'election', 'crypto_scheme': 'paillier'}

    for spelling in ('0', 'false', 'False', '', 'off', 'no'):
      form = ElectionForm(data={**base, 'paillier_use_crt_proofs': spelling})
      self.assertTrue(form.is_valid(), form.errors)
      self.assertFalse(form.cleaned_data['paillier_use_crt_proofs'],
                       f'{spelling!r} should disable CRT proofs')

    for spelling in ('1', 'true', 'True', 'on', 'yes'):
      form = ElectionForm(data={**base, 'paillier_use_crt_proofs': spelling})
      self.assertTrue(form.is_valid(), form.errors)
      self.assertTrue(form.cleaned_data['paillier_use_crt_proofs'],
                      f'{spelling!r} should enable CRT proofs')

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
    self.assertEqual(form.cleaned_data['paillier_djn41_mode'], 'off')

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

  def test_djn41_election_freezes_tallies_and_decrypts(self):
    """
    The same pipeline in each DJN §4.1 mode: freeze -> vote -> tally ->
    decrypt through Helios's own model methods, with an exact tally, ballots
    whose randomness comes from the mode's range, and verifying decryption
    proofs.

    The trustee key comes from 256-bit safe primes, because full-size ones
    take minutes each; PaillierKeyGenerationTests covers the full size.
    Everything else is the real pipeline.
    """
    from unittest import mock

    from helios import views
    from helios.models import CastVote, Voter
    from helios.views import crypto_params_for
    from helios.workflows.homomorphic import EncryptedVote

    for mode in ('short', 'long'):
      with self.subTest(mode=mode):
        e = self._election('paillier', f'e2e-djn-{mode}')
        e.paillier_djn41_mode = mode
        with mock.patch.object(views.PAILLIER_PARAMS, 'key_size', 256):
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
        self.assertEqual(e.public_key.djn41_mode, mode)

        ballots = [[0], [0, 1], [2], [0, 2], [1]]
        for i, answer in enumerate(ballots):
          voter = Voter.objects.create(
            election=e, uuid=f'djn-{mode}-voter-{i}',
            voter_login_id=f'v{i}', voter_name=f'Voter {i}',
            voter_email=f'v{i}@example.com')
          vote = EncryptedVote.fromElectionAndAnswers(e, [answer])
          for r in vote.encrypted_answers[0].randomness:
            self.assertLess(r, e.public_key.exponent_bound)
          self.assertTrue(vote.verify(e), f'{mode} ballot {i} failed to verify')

          cv = CastVote(voter=voter, vote=vote, vote_hash=vote.hash,
                        cast_at=datetime.datetime.utcnow())
          cv.save()
          voter.store_vote(cv)

        e.compute_tally()
        self.assertEqual(e.encrypted_tally.num_tallied, len(ballots))

        e.helios_trustee_decrypt()
        e.combine_decryptions()

        # A=3, B=2, C=2
        self.assertEqual(e.result, [[3, 2, 2]], f'{mode} tally is wrong')
        self.assertTrue(e.get_helios_trustee().verify_decryption_proofs(),
                        f'{mode} decryption proofs did not verify')


class DJN41ModeMigrationTests(TransactionTestCase):
  """
  Migration 0013: the boolean paillier_use_djn41 becomes paillier_djn41_mode.

  True could only ever select the short-exponent variant, so it becomes
  'short', and False becomes 'off' -- for soft-deleted elections too, which
  the default manager would hide. And back again, where 'long' has no boolean
  of its own and becomes True.
  """

  BEFORE = [('helios', '0012_election_paillier_use_crt_proofs_and_more')]
  AFTER = [('helios', '0013_election_paillier_djn41_mode')]

  def _migrate(self, targets):
    from django.db import connection
    from django.db.migrations.executor import MigrationExecutor

    executor = MigrationExecutor(connection)
    executor.migrate(targets)
    return executor.loader.project_state(targets).apps

  def tearDown(self):
    # leave the schema as every later test expects it, pass or fail
    from django.db import connection
    from django.db.migrations.executor import MigrationExecutor

    executor = MigrationExecutor(connection)
    executor.migrate(executor.loader.graph.leaf_nodes())

  def test_0013_maps_the_boolean_onto_the_mode_and_back(self):
    import uuid as uuid_mod

    apps = self._migrate(self.BEFORE)
    User = apps.get_model('helios_auth', 'User')
    Election = apps.get_model('helios', 'Election')

    admin = User.objects.create(user_type='password', user_id='migration',
                                name='Migration', info={})

    def election(short_name, djn41, deleted_at=None):
      return Election.objects.create(
        admin=admin, uuid=str(uuid_mod.uuid4()), short_name=short_name,
        name=short_name, description='', election_type='election',
        crypto_scheme='paillier', cast_url='http://localhost/cast',
        paillier_use_djn41=djn41, deleted_at=deleted_at).id

    ids = {
      'djn41': election('mig-djn41', True),
      'standard': election('mig-standard', False),
      'soft-deleted djn41': election('mig-deleted', True,
                                     deleted_at=datetime.datetime.utcnow()),
      'later long': election('mig-long', False),
    }

    Election = self._migrate(self.AFTER).get_model('helios', 'Election')
    self.assertEqual(
      {k: Election.objects.get(id=v).paillier_djn41_mode for k, v in ids.items()},
      {'djn41': 'short', 'standard': 'off', 'soft-deleted djn41': 'short',
       'later long': 'off'})

    Election.objects.filter(id=ids['later long']).update(
      paillier_djn41_mode='long')

    Election = self._migrate(self.BEFORE).get_model('helios', 'Election')
    self.assertEqual(
      {k: Election.objects.get(id=v).paillier_use_djn41 for k, v in ids.items()},
      {'djn41': True, 'standard': False, 'soft-deleted djn41': True,
       'later long': True})


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

  def test_audit_verifier_loaders_load_paillier(self):
    """
    The single-ballot audit verifier has two loaders of its own: the page, and
    the worker it hands verification to. helios.js calls
    CRYPTO.publicKeyFromJSONObject, which scheme_adapters.js defines, so a
    loader that includes helios.js without it cannot even parse an election.
    Both loaders lacked it, and every audit -- ElGamal included -- failed with
    "CRYPTO is not defined".
    """
    elgamal, paillier, adapters, helios = (
      'js/jscrypto/%s' % name for name in
      ('elgamal.js', 'paillier.js', 'scheme_adapters.js', 'helios.js'))

    for loader in ('single-ballot-verify.html', 'verifierworker.js'):
      with self.subTest(loader=loader):
        with open(os.path.join(self.BOOTH, loader)) as f:
          source = f.read()

        for script in (elgamal, paillier, adapters, helios):
          self.assertIn(script, source, f'{loader} does not load {script}')

        # the same order constraint as the booth worker
        self.assertLess(source.index(elgamal), source.index(paillier))
        self.assertLess(source.index(paillier), source.index(adapters))
        self.assertLess(source.index(adapters), source.index(helios))

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

    # Paillier shapes are re-routed -- a public key in both of its shapes.
    self.assertEqual(resolve({'n': '1', 'g': '2'}, 'legacy/EGPublicKey'),
                     'paillier/PublicKey')
    self.assertEqual(
      resolve({'n': '1', 'g': '2', 'h': '3', 'hn': '4', 'djn41_mode': 'short'},
              'legacy/EGPublicKey'),
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
