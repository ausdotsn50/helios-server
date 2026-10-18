"""
Paillier cryptosystem for the Helios Voting System.
"""

import math

from Crypto.Hash import SHA1
from Crypto.Util import number

from helios.crypto.utils import random

# Bits per prime. |n| = 2*KEY_SIZE = 2048, matching ElGamal's 2048-bit p.
DEFAULT_KEY_SIZE = 1024

# Minimum modulus width accepted by validate_pk_params. Tests construct keys far
# below this deliberately and never route them through validation.
MIN_MODULUS_BITS = 2048


# Util .py counterpart
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
  Single-commitment case, used by the proof of correct decryption (2.8).

  Wraps the disjunctive generator with a one-element list, exactly as
  EG_fiatshamir_challenge_generator wraps EG_disjunctive_challenge_generator.
  """
  return paillier_disjunctive_challenge_generator([commitment])

# Paillier cryptosystem
class Paillier:
  """
  Counterpart of elgamal.Cryptosystem.
  """

  def __init__(self, key_size=DEFAULT_KEY_SIZE):
    self.key_size = key_size

  # Which datatype a trustee public key of this scheme serializes as.
  public_key_datatype = 'paillier/PublicKey'

  # Paillier generates no trustee proof of knowledge of the secret key, so
  # there is no challenge generator for one. See PaillierSecretKey.prove_sk.
  dlog_challenge_generator = None

  def generate_keypair(self):
    keypair = PaillierKeyPair()
    keypair.generate(self.key_size)
    return keypair

  def toJSONDict(self):
    return {'key_size': str(self.key_size)}

  @classmethod
  def fromJSONDict(cls, d):
    return cls(key_size=int(d['key_size']))


class PaillierKeyPair:
  """Counterpart of elgamal.KeyPair."""

  def __init__(self):
    self.pk = PaillierPublicKey()
    self.sk = PaillierSecretKey()

  def generate(self, key_size=DEFAULT_KEY_SIZE):
    """
    Build a keypair

        p, q  <- distinct random primes, exactly `key_size` bits each
        n     =  p*q
        g     =  1 + n
        lambda=  lcm(p-1, q-1)
        mu    =  lambda^-1 mod n
    """
    def new_prime():
      # Return a random strong N-bit prime number. In this context, p is a strong prime if p-1 and p+1 have at least one large prime factor.
      return number.getStrongPrime(key_size) # From pycryptodome library

    # getStrongPrime ensures equal bit length, passes gcd check
    p = new_prime()
    q = new_prime()
    while q == p:
      q = new_prime()

    self._assign(p, q)
    return self

  def _assign(self, p, q):
    """Shared by generate() and the fixed-prime construction used in tests."""
    n = p * q

    self.pk.n = n
    self.pk.g = n + 1

    self.sk.p = p
    self.sk.q = q
    self.sk.lambda_ = math.lcm(p - 1, q - 1)
    self.sk.mu = number.inverse(self.sk.lambda_, n) # yptodome: The inverse of u mod v.
    self.sk.public_key = self.pk

    return self

  @classmethod
  def from_primes(cls, p, q):
    """
    Construct from fixed primes.

    Used by the test suite -- for small keys that keep the suite fast, and for
    the deterministic (p, q, m, v) vectors checked against the external oracle
    in test 14.
    """
    kp = cls()
    return kp._assign(p, q)


class PaillierPublicKey:
  """Counterpart of elgamal.PublicKey / algs.EGPublicKey."""

  # Declared on the wrapped object so LDObject.instantiate routes it to the
  # Paillier serializer even when the field's static type hint says ElGamal.
  # See helios/datatypes/__init__.py.
  datatype = 'paillier/PublicKey'

  # Shared tally code with ElGamal (specify)
  has_dlog = False

  def __init__(self, n=None, g=None):
    self.n = n
    self.g = g

  @property
  def n2(self):
    """Derived, never serialized."""
    return self.n * self.n

  def encrypt_with_r(self, plaintext, r, encode_message=False):
    if encode_message:
      raise Exception(
        "encode_message has no meaning under Paillier: the plaintext is the "
        "integer itself, with no subgroup encoding. The parameter exists only "
        "for signature parity with EGPublicKey.encrypt_with_r.")

    m = plaintext.m if hasattr(plaintext, 'm') else plaintext
    n, n2 = self.n, self.n2

    blinding = pow(r, n, n2)

    return PaillierCiphertext(((1 + m * n) * blinding) % n2, self)

  def encrypt_return_r(self, plaintext):
    """
    Encrypt and hand back the randomness, which the proofs need as witness.
    """
    r = self.random_randomness()
    return [self.encrypt_with_r(plaintext, r), r]

  def encrypt(self, plaintext):
    return self.encrypt_return_r(plaintext)[0]

  def __mul__(self, other):
    """
    Refuse to combine Paillier trustee keys
    """
    if other == 0 or other == 1:
      return self

    raise NotImplementedError(
      "Paillier trustee keys cannot be combined; threshold Paillier requires "
      "DKG, which is out of scope.")

  # Counterpart of helios/crypto/scheme_adapters.py's ElGamal side. Keeping
  # these on the public key is what lets workflows/homomorphic.py hold zero
  # references to any scheme.

  def generate_plaintexts(self, min=0, max=1):
    return [PaillierPlaintext(i, self) for i in range(min, max + 1)]

  def random_randomness(self):
    """
    Fresh encryption randomness
    """
    return random_z_star_n(self.n)

  def combine_randomness(self, acc, r):
    """
    How the overall proof's combined witness is accumulated
    """
    return (acc * r) % self.n

  @property
  def randomness_identity(self):
    """Multiplicative 1 for the standard path."""
    return 1

  def tally_decoder(self, num_tallied):
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

  # mirrors EGPublicKey.validate_pk_params
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

  # SERIALIZATION
  def to_dict(self):
    # g is serialized even though it equals n+1: it costs nothing, mirrors
    # EGPublicKey's four redundant fields, and gives validate_pk_params
    # something to check.
    return {'n': str(self.n), 'g': str(self.g)}

  toJSONDict = to_dict

  @classmethod
  def from_dict(cls, d):
    pk = cls(n=int(d['n']), g=int(d['g']))
    pk.validate_pk_params()
    return pk

  fromJSONDict = from_dict

  def __eq__(self, other):
    if other is None or not isinstance(other, PaillierPublicKey):
      return False
    return self.n == other.n and self.g == other.g

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
  # see decrypt_factor. Kept separate so the two can be measured independently.
  use_crt_for_proofs = True

  @property
  def pk(self):
    """Alias, as elgamal.SecretKey has."""
    return self.public_key

  @pk.setter
  def pk(self, value):
    self.public_key = value

  # CRT precomputation
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

  # CRT exponentiation
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
    """
    p, q = self.p, self.q
    if p is None or q is None:
      raise Exception("cannot derive CRT constants without p and q")

    self._h_p = number.inverse((-q) % p, p)
    self._h_q = number.inverse((-p) % q, q)
    self._p_inv = number.inverse(p, q)

    # For CRT exponentiation modulo n^2 = p^2 * q^2 (see crt_pow_n2).
    self._p2_inv_q2 = number.inverse((p * p) % (q * q), q * q)

  def decrypt_no_crt(self, ciphertext):
    """
        Dec(c) = L(c^lambda mod n^2) * mu  mod n
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
        m   = m_p + p * ((m_q - m_p) * p_inv mod q)
    """
    p, q = self.p, self.q
    c = ciphertext.c if hasattr(ciphertext, 'c') else ciphertext

    m_p = ((pow(c, p - 1, p * p) - 1) // p * self.h_p) % p
    m_q = ((pow(c, q - 1, q * q) - 1) // q * self.h_q) % q

    # Garner's Formula to return factor=m
    # https://www.johndcook.com/blog/2023/09/14/garners-algorithm/
    return m_p + p * (((m_q - m_p) * self.p_inv) % q)

  def decryption_factor(self, ciphertext):
    return self.decrypt_factor(ciphertext)

  def decrypt(self, ciphertext, dec_factor=None, decode_m=False):
    """Mirrors EGSecretKey.decrypt's signature. Returns a PaillierPlaintext."""
    if dec_factor is None:
      dec_factor = self.decryption_factor(ciphertext)
    return PaillierPlaintext(dec_factor, self.public_key)

  def decryption_factor_and_proof(self, ciphertext, challenge_generator=None):
    """
    Counterpart of EGSecretKey.decryption_factor_and_proof.
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
    # Turning use_crt_for_proofs off measures what CRT is worth on the proof.
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

  def prove_sk(self, challenge_generator):
    """
    Returns None. Paillier generates no trustee proof of knowledge of the
    secret key.

    Its analogue, a proof of knowledge of the factorization (Poupard-Stern),
    is not implemented.

    Trustee.pok is LDObjectField(type_hint='legacy/DLogProof', null=True), so
    None persists cleanly.

    Deliberately NOT an empty proof object: an empty proof is a proof that
    verifies vacuously, which is worse than an absent one.
    """
    return None

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

  def _statement_for(self, plaintext):
    """
    Statement for "this ciphertext encrypts m_j":
    """
    n, n2 = self.pk.n, self.pk.n2
    m = plaintext.m if hasattr(plaintext, 'm') else plaintext
    return (self.c * (1 - m * n)) % n2

  def generate_encryption_proof(self, plaintext, randomness, challenge_generator):
    return PaillierZKProof.generate(
      self._statement_for(plaintext), randomness,
      self.pk, challenge_generator)

  def simulate_encryption_proof(self, plaintext, challenge=None):
    return PaillierZKProof.simulate(
      self._statement_for(plaintext), self.pk, challenge)

  def generate_disjunctive_encryption_proof(self, plaintexts, real_index,
                                            randomness, challenge_generator):
    """
    CDS 1-out-of-L composition over L instances of Pi_root.
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

    for i in range(len(plaintexts)): # similar w/ elgamal.py verif
      if not self.verify_encryption_proof(plaintexts[i], proof.proofs[i]):
        return False

    # e0+e1+...+en = hash(a0,a1,...,an) mod 2^160
    return (challenge_generator([p.commitment for p in proof.proofs]) ==    # Hash commitments
            (sum([p.challenge for p in proof.proofs]) % CHALLENGE_MODULUS)) # Sum the challenges

  def decrypt(self, decryption_factors, public_key):
    if len(decryption_factors) != 1:
      raise NotImplementedError(
        "Paillier elections support exactly one trustee, got %s decryption "
        "factor sets; threshold Paillier requires DKG, which is out of scope. " % len(decryption_factors))

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


class PaillierZKProof:
  """
  Counterpart of algs.EGZKProof. DJN 5.2 at s = 1, the Paillier analogue of
  Chaum-Pedersen.

      Statement:  u in Z*_{n^2} is an n-th power: exists v in Z*_n, u = v^n mod n^2
      Witness:    v

      Prove:      r <-$ Z*_n
                  a = r^n mod n^2
                  e = challenge_generator(a)          in [0, 2^160)
                  z = r * v^e mod n                   <- MOD n. NOT mod n^2.

      Verify:     z^n = a * u^e  (mod n^2)
                  and gcd(z,n) = gcd(u,n) = gcd(a,n) = 1
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
    """
    n, n2 = pk.n, pk.n2
    r = random_z_star_n(n)

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
    """
    e in [0, 2^160), z^n == a * u^e (mod n^2), plus unit checks on z, u and a.
    """
    n, n2 = pk.n, pk.n2

    if self.commitment is None or self.challenge is None or self.response is None:
      return False

    if not (0 <= self.challenge < CHALLENGE_MODULUS):  # check cond1: 0 <= e < 2^160
      return False

    # Unit checks. Without them a malicious prover could submit a value sharing
    # a factor with n, for which the exponentiation identities do not hold.
    for value in (self.response, u, self.commitment): # check cond2: u,a,z prime to n
      if value % n == 0 or math.gcd(value, n) != 1:
        return False

    left = pow(self.response, n, n2)  # z^n mod n^2
    right = (self.commitment * pow(u, self.challenge, n2)) % n2   # a * u^e mod n^2

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
  Special-soundness extraction
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
