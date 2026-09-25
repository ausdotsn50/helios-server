# Paillier-Helios — build specification

**Handoff document for Claude Code.** Companion to `PAILLIER_MASTERPLAN.md`, which is the
authority on *what* and *why*; this document is the authority on *how*. Where they disagree, the
masterplan wins and this file is wrong — say so rather than guessing.

Thesis: *System-Level Performance Comparison of Paillier and Exponential ElGamal using the Helios
Voting System* (A. D. Almazan, UP Visayas Tacloban).

```
repos      helios-server   HEAD d61eaa8  (fork of benadida/helios-server @ c7d5e60)
           workload        HEAD 1edd9b4
stack      Django + PostgreSQL + Celery, Python 3.13, uv
booth      pure-JS jsbn bignum, no native BigInt
```

---

> **Cross-references.** Every bare `§` in this file points at a section of **this file**. The
> masterplan has its own §1–§13 covering different material — references to it always say
> "masterplan" explicitly. Both documents are in the repository root.

## 0. Rules of engagement

Read all of §1, "What you must know about this codebase before you start", before writing any
code.

1. **This is a controlled experiment.** The measured quantity is the cryptosystem, not the
   pipeline. Every change is additive or a branch that leaves the ElGamal path byte-identical.
2. **Never modify `helios/crypto/algs.py` or `helios/crypto/elgamal.py`.** Not one line. If you
   believe a change there is required, stop and report instead.
3. **Work milestone by milestone.** Each has an explicit gate. Do not begin a milestone whose
   predecessor's gate is red. Report at every gate: what passed, what did not, what you changed.
4. **Do not invent cryptographic parameters.** Every constant, modulus, hash and reduction is
   specified in **§2, "Cryptographic contracts", of this document**. If something you need is not
   specified there, stop and ask — a guessed reduction modulus produces code that passes every
   local test and fails at cast time.
5. **Two-space indentation** in `helios/`, matching the surrounding files. Four spaces in
   `workload/`. Match each file's existing style over any global preference.
6. **No new runtime dependencies** in `helios-server`. `phe` and `pytest` may be added as test-only
   dependencies. `phe` is GPLv3 — it may be imported by tests, and **no line of it may be copied
   into the source tree**.
7. When a step is blocked, leave the tree green: no half-applied refactor, no commented-out
   ElGamal code.

---

## 1. What you must know about this codebase before you start

Five things here are not what a reasonable person would assume. Every one of them has produced a
wrong plan already.

### 1.1 The tally code is not where the old spec says

`EncryptedAnswer`, `EncryptedVote`, `Tally` and `DLogTable` live in
**`helios/workflows/homomorphic.py`** (442 lines).

`helios/crypto/electionalgs.py` contains same-named classes from the pre-2011 `HeliosObject`
lineage. **They are dead.** Nothing imports them except `helios/tests.py`, and only for
`one_question_winner`. Do not edit that file.

### 1.2 There are two ElGamal implementations and they are both live

- `helios/crypto/algs.py` — `EGPublicKey`, `EGCiphertext`, `EGZKProof`, the challenge generators.
  Used by `models.py` and `homomorphic.py`.
- `helios/crypto/elgamal.py` — `PublicKey`, `Ciphertext`, `ZKProof`. Used by
  `helios/datatypes/legacy.py` as every `WRAPPED_OBJ_CLASS`.

At runtime an election's `public_key` deserializes into a `helios.crypto.elgamal.PublicKey`, and
`homomorphic.py` calls methods on it while separately referring to `algs.EGPlaintext` and
`algs.EG_disjunctive_challenge_generator` in the same function. Objects of both lineages coexist
in one ballot construction.

**Consequence for you:** write **one** `helios/crypto/paillier.py` carrying the whole surface.
Point the new datatypes' `WRAPPED_OBJ_CLASS` at it. Do not create a second Paillier module to
mirror the split.

### 1.3 `core/BigInteger` serializes zero as null — and this will corrupt Paillier tallies

`helios/datatypes/core.py`:

```python
class BigInteger(LDObject):
    WRAPPED_OBJ_CLASS = int
    def toDict(self, complete=False):
        if self.wrapped_obj:          # ← 0 is falsy
            return str(self.wrapped_obj)
        else:
            return None
```

Harmless for ElGamal: decryption factors are group elements in `[1, p)`, never zero. **Fatal for
Paillier**, where the decryption factor *is* the plaintext tally (§2.7) and a candidate with zero
votes produces exactly `0`. `Trustee.decryption_factors` is typed
`arrayOf(arrayOf('core/BigInteger'))`, so a zero tally would round-trip as `null`.

**Fix in milestone B0:** change the guard to `if self.wrapped_obj is not None:`. This is a bug
fix, not a scheme change. It alters ElGamal output only for a value of exactly `0`, which occurs
in the ElGamal path with probability about `2⁻¹⁶⁰` (a zero challenge). Record it in the milestone
report, and confirm it against the golden-ballot test (§7, test 15).

Add: `test_bigint_zero_roundtrips` — `BigInteger(0).toDict() == "0"` and `fromDict("0") == 0`.

### 1.4 `LDObject.toDict` crashes when a datatype declares no structured fields

```python
    def toDict(self, alternate_fields=None, complete=False):
        fields = self.FIELDS
        if not self.structured_fields:
            if self.wrapped_obj.alias is not None:      # ← Voter-specific, AttributeError otherwise
```

**Requirement:** every Paillier LDObject must declare **all** of its fields in
`STRUCTURED_FIELDS`. Every Paillier field is a big integer, so this is natural — but a datatype
that forgets it raises `AttributeError: 'PaillierCiphertext' object has no attribute 'alias'`
from deep inside serialization, which is a confusing failure. §5.2 gives the declarations; use
them verbatim.

### 1.5 Helios's own randomness sampler is biased. Do not copy it

`helios/crypto/utils.py`:

```python
def random_mpz_lt(maximum, strong_random=random):
    n_bits = int(math.floor(math.log(maximum, 2)))
    res = strong_random.getrandbits(n_bits)
    while res >= maximum:
        res = strong_random.getrandbits(n_bits)
    return res
```

With `floor(log2(maximum))` bits the draw can never reach `maximum`, so the rejection loop never
fires and the output is uniform on `[0, 2^floor(log2 max))` rather than `[0, maximum)`. For
Helios's 256-bit `q` this makes roughly the top 5.5% of `Z_q` unreachable. The file `algs.py`
opens with `FIXME: improve random number generation`, so this is a known-rough area.

**Do not replicate it.** §2.2 specifies a correct sampler for Paillier. Sampling cost is
negligible either way, so this costs nothing measurable and avoids building a known bias into the
new arm. Report it in the B2 milestone note — it is a finding for the thesis's
implementation-quality discussion, not just an implementation detail.

### 1.6 The booth loads a compiled bundle; the Web Worker loads individual files

`heliosbooth/vote.html` has every `<script>` tag commented out and loads
`js/20160507-helios-booth-compressed.js`. `heliosbooth/boothworker-single.js` `importScripts` the
individual files.

The measurement harness drives the **main thread** via `/booth/vote.html`, so it exercises the
bundle. A real voter's encryption runs in the **worker**, off the individual files. Add
`paillier.js` to both, or half your tests will pass against code the other half never loads.

---

## 2. Cryptographic contracts

Normative. Every value, modulus and encoding below is fixed. Implement exactly.

Parameters: `k = 1024` (prime size) → `|n| = 2048`, `|n²| = 4096`. Challenge width `t = 160`.
`L(x) = (x−1)/n`.

### 2.1 Key generation

```
p, q   ←  distinct random primes, exactly 1024 bits each
n      =  p·q
g      =  1 + n
λ      =  lcm(p−1, q−1)
μ      =  λ⁻¹ mod n
```

`μ` reduces to a modular inverse because `g = 1+n` gives `g^λ ≡ 1 + λn (mod n²)`, hence
`L(g^λ) = λ`. Assert this in a test: compute `μ` both ways and require equality.

Reject a keypair if `p == q`, if `|n| ≠ 2048`, or if `gcd(λ, n) ≠ 1`.

Use `Crypto.Util.number.getStrongPrime(1024)` or `getPrime(1024, randfunc)` from PyCryptodome,
which is already a dependency. Do not add `gmpy2`.

### 2.2 Randomness

```python
def random_lt(maximum):
  """Uniform on [0, maximum). Correct rejection sampling — see §1.5."""
  n_bits = maximum.bit_length()
  res = random.getrandbits(n_bits)
  while res >= maximum:
    res = random.getrandbits(n_bits)
  return res

def random_z_star_n(n):
  """Uniform on Z*_n."""
  while True:
    v = random_lt(n)
    if v > 0 and math.gcd(v, n) == 1:
      return v
```

`random` is `helios.crypto.utils.random` (PyCryptodome `StrongRandom`). The `gcd` check will
essentially never fire; keep it, because a `v` sharing a factor with `n` would leak the
factorization.

JavaScript equivalent: `Random.getRandomInteger(max)` from `heliosbooth/js/jscrypto/random.js`,
which draws `ceil(bitLength/32)+2` words from `sjcl.random` and reduces — 64 bits of headroom, so
bias is negligible. **Use it. Do not introduce another RNG**, and do not pull in jsbn's
`prng4.js`/`rng.js`.

### 2.3 Encryption, decryption, addition

```
Enc(m, v)  =  (1 + m·n) · v^n  mod n²          v ←$ Z*_n
Dec(c)     =  L(c^λ mod n²) · μ  mod n
c₁ ⊞ c₂    =  c₁ · c₂  mod n²
```

The message component is **one multiplication, never an exponentiation** — this is the mandated
`(1+n)^m = 1+mn` optimization. Only `v^n` costs.

Two identities used throughout, both exact mod n²:

```
(1+n)^{−j}  ≡  1 − j·n   (mod n²)          →  u_j = c · (1 − j·n) mod n²,  one multiply
Enc(0, v)   =  v^n mod n²                  →  an encryption of zero IS an n-th power
```

The second is why Π_root is the right base protocol: proving `c` encrypts `m_j` is exactly
proving `c·(1 − m_j n)` is an n-th power.

### 2.4 CRT decryption — mandatory

DJN §4.2 gives one sentence, not an algorithm. This is derived; validate against `phe` (§7,
test 14).

Precompute once per key:

```
L_p(x) = (x−1)/p                 L_q(x) = (x−1)/q
h_p    = L_p(g^{p−1} mod p²)⁻¹ mod p        = (−q)⁻¹ mod p
h_q    = L_q(g^{q−1} mod q²)⁻¹ mod q        = (−p)⁻¹ mod q
p_inv  = p⁻¹ mod q
```

The closed forms follow because `(1+pq)^{p−1} ≡ 1 + (p−1)pq (mod p²)` — every higher binomial
term carries `(pq)² ≡ 0 (mod p²)`. **Compute `h_p` both ways in a test and assert equality**; it
is a free check that the derivation and the code agree.

Decrypt:

```
m_p  =  L_p(c^{p−1} mod p²) · h_p  mod p
m_q  =  L_q(c^{q−1} mod q²) · h_q  mod q
m    =  m_p + p · ((m_q − m_p) · p_inv  mod q)          (Garner)
```

Valid because every tally satisfies `m < n`.

Expose **both** paths — `decrypt(c)` using CRT, and `decrypt_no_crt(c)` using `λ` and `μ` — as
separate methods. The ablation in B10 measures the difference, and test 13 asserts they agree.

### 2.5 Π_root — proof of knowledge of an n-th root

DJN §5.2 at `s = 1`. The Paillier analogue of Chaum–Pedersen.

```
Statement:  u ∈ Z*_{n²} is an n-th power:  ∃ v ∈ Z*_n with u = v^n mod n²
Witness:    v

Prove:      r ←$ Z*_n
            a = r^n mod n²
            e = challenge_generator(a)            ∈ [0, 2^160)
            z = r · v^e mod n                     ← MOD n. NOT mod n².

Verify:     z^n ≡ a · u^e   (mod n²)
            and gcd(z, n) == gcd(u, n) == gcd(a, n) == 1

Simulate:   given e:   z ←$ Z*_n
                       a = z^n · modinv(u^e mod n², n²) mod n²
```

> **The single most important line in this document.** `z` is reduced **mod n**, not mod n².
> Reducing mod n² still verifies — `z^n mod n²` depends only on `z mod n²` — but makes the
> honest branch's `z` roughly twice the bit length of every simulated branch's, so the real
> branch is identifiable by inspection and ballot secrecy is gone. This is the exact bug in
> `ishaq/Paillier-E-Voting`. It is invisible to functional testing. Test 11 exists solely to
> catch it.

Special soundness (needed for test 10): from `(a, e, z)` and `(a, e′, z′)` with `e ≠ e′`, set
`d = e − e′`. Since `0 < |d| < 2^160 < min(p, q)`, `gcd(d, n) = 1`, so extended-gcd gives `α, β`
with `αd + βn = 1` and

```
v = (z · z′⁻¹)^α · u^β  mod n
```

### 2.6 The 1-out-of-L disjunctive composition

CDS OR-composition over L instances of Π_root. Cite Cramer–Damgård–Schoenmakers 1994, not DJN —
DJN gives 1-out-of-2 only, and Q1 needs L = 13.

```
Given u_0 … u_{L−1}, real index j*, witness v:

  1.  for j ≠ j*:   e_j ←$ [0, 2^160)
                    z_j ←$ Z*_n
                    a_j = z_j^n · modinv(u_j^{e_j} mod n², n²) mod n²

  2.  for j = j*:   r ←$ Z*_n
                    a_{j*} = r^n mod n²

  3.  s   = challenge_generator([a_0, …, a_{L−1}])

  4.  e_{j*} = (s − Σ_{j≠j*} e_j)  mod 2^160
      z_{j*} = r · v^{e_{j*}} mod n

Verify:  Σ_j e_j ≡ challenge_generator([a_0, …, a_{L−1}])  (mod 2^160)
         z_j^n   ≡ a_j · u_j^{e_j}  (mod n²)                for every j
```

**Mirror Helios's control flow exactly**, including the callback: `generate_disjunctive_encryption_proof`
simulates every branch but `real_index`, then generates the real proof with a
`real_challenge_generator` closure that plants the real commitment, hashes all commitments, and
subtracts the simulated challenges. The only substantive difference from ElGamal is that Helios
reduces the real challenge `% pk.q` and you reduce `% 2**160`.

Build the proof list **by index**, never by appending — the real branch's position must not be
inferable from anything but the (indistinguishable) values.

### 2.7 The two ballot proofs

**Individual — "encrypts 0 or 1"**, one per answer slot:

```
u_0 = c                          # (1+n)^{−0} = 1
u_1 = c · (1 − n)  mod n²        # (1+n)^{−1} ≡ 1 − n
real index = the encrypted bit,  witness = the encryption randomness v
L = 2
```

**Overall — "selection count in [min, max]"**, one per question:

```
C   = Π_i c_i  mod n²                       homomorphic product of the question's ciphertexts
V   = Π_i v_i  mod n                        combined witness
u_j = C · (1 − (min + j)·n)  mod n²         j = 0 … L−1,   L = max − min + 1
real index = (number selected) − min
```

`V` is correct because `(Π v_i)^n = Π v_i^n mod n²`. It is the **multiplicative** analogue of
Helios's `randomness_sum = (randomness_sum + r) % pk.q` — this is the one place where "identical
control flow" needs a named abstraction rather than a shared expression, and §4.2's
`combine_randomness` is it.

2025 NLE face: Q1 (66 answers, min 0, max 12) → **L = 13**. Q2 (156 answers, min 0, max 1) →
**L = 2**.

### 2.8 Proof of correct decryption

```
Prover (trustee), given tally ciphertext c and recovered plaintext m:
  1.  u = c · (1 − m·n)  mod n²
  2.  d = n⁻¹ mod λ
  3.  v = u^d mod n                          the randomness, recovered
  4.  Π_root on (u, v), Fiat–Shamir          → (a, e, z)

Verifier (public), given c, claimed m, (a, e, z):
      e == challenge_generator([a])   and   z^n ≡ a · (c·(1 − m·n))^e  (mod n²)
```

Step 3 is valid because `u ≡ v^n (mod n)` and `v^{nd} = v^{1+κλ} ≡ v (mod n)` by Carmichael.
Steps 3 and 4's commitment are CRT-accelerable — only the trustee runs them.

**Hash the commitment only, not the statement.** That is weaker than best practice, and it is
exactly what Helios's ElGamal path does (`decryption_factor_and_proof` passes only
`proof.commitment` to `EG_fiatshamir_challenge_generator`). Matching it keeps the two arms
symmetric in both cost and security posture.

### 2.9 The challenge generator — byte-exact, both languages

This is where cross-language builds fail silently. Milestone B1 tests it before anything else
exists.

```
input      =  ",".join(decimal(a_j) for j in 0 … L−1)
challenge  =  int(SHA1(utf8(input)).hexdigest(), 16)          ∈ [0, 2^160)
```

Invariants that must hold identically in Python and JavaScript:

- **Radix 10**, no leading zeros, no sign. All values positive.
- **Separator** is one ASCII comma. No spaces. No trailing comma.
- **UTF-8** encoding of an ASCII-only string.
- **Canonicalise before stringifying**: `a` reduced mod n², `z` mod n, `e` mod 2^160. Two
  implementations that disagree only about whether a value was reduced produce different hashes.
- SHA-1 output is exactly 160 bits, so `challenge < 2^160` always. The reduction is a no-op; keep
  it anyway, because it documents the invariant.
- The single-commitment case (§2.8) is this generator called with a one-element list, exactly as
  `EG_fiatshamir_challenge_generator` wraps `EG_disjunctive_challenge_generator`.

Reference implementations. These are normative — copy them.

```python
# helios/crypto/paillier.py
from Crypto.Hash import SHA1

CHALLENGE_BITS = 160
CHALLENGE_MODULUS = 1 << CHALLENGE_BITS

def paillier_disjunctive_challenge_generator(commitments):
  """commitments: list of int (the a_j). Mirrors algs.EG_disjunctive_challenge_generator."""
  string_to_hash = ",".join(str(a) for a in commitments)
  return int(SHA1.new(bytes(string_to_hash, 'utf-8')).hexdigest(), 16) % CHALLENGE_MODULUS

def paillier_fiatshamir_challenge_generator(commitment):
  return paillier_disjunctive_challenge_generator([commitment])
```

```javascript
// heliosbooth/js/jscrypto/paillier.js
Paillier.CHALLENGE_BITS = 160;
Paillier.CHALLENGE_MODULUS = BigInt.ONE.shiftLeft(160);

Paillier.disjunctive_challenge_generator = function(commitments) {
  var strings_to_hash = _(commitments).map(function(a) {
    return a.toJSONObject();          // BigInteger.toString(), radix 10 — same as ElGamal
  });
  return new BigInt(hex_sha1(strings_to_hash.join(",")), 16).mod(Paillier.CHALLENGE_MODULUS);
};

Paillier.fiatshamir_challenge_generator = function(commitment) {
  return Paillier.disjunctive_challenge_generator([commitment]);
};
```

Note `a.toJSONObject()` rather than `a.toString()` — `bigint.js` defines `toJSONObject` as
`this.toString()`, and `elgamal.js` uses the former with the comment "because of IE weirdness".
Match it.

### 2.10 Why t = 160 is sound, and why not to change it

Extraction requires `2^t <` the smallest prime factor of `n`. At `t = 160` and 1024-bit primes
there are about 864 bits of margin. Reusing Helios's SHA-1 generator therefore satisfies the
bound **and** holds the hash function constant across both arms, which removes a hashing-cost
difference from the comparison.

Do not "improve" this to SHA-256. It would introduce an asymmetry the thesis then has to explain.

---

## 3. Milestones

Ordered. Each gate is binary. Report at each.

| # | Milestone | Repo | Gate |
|---|---|---|---|
| A1 | Harness scheme guard | workload | §8.1 |
| A2 | Scheme-aware Stage 4 | workload | §8.2 |
| A3 | Acceptance scheme-awareness | workload | §8.3 |
| B0 | Datatype dispatch spike + `core/BigInteger` fix | helios-server | §5.1 |
| B1 | Cross-language challenge agreement | both | §6.1 |
| B2 | `paillier.py` — keygen, enc, dec, CRT, add | helios-server | tests 1–4, 13, 14 |
| B2a | Modexp microbenchmark | helios-server | §9 |
| B3 | `paillier.py` — Π_root, 1-out-of-L, decryption proof | helios-server | tests 5–8, 10–12 |
| B4 | `homomorphic.py` scheme-agnostic refactor | helios-server | test 15 + upstream suite |
| B5 | `paillier.js` | helios-server | test 9 |
| B6 | Bundle + worker wiring | helios-server | §6.4 |
| B7 | Datatypes, models, views wired | helios-server | end-to-end in browser |
| B8 | Ballot-size canary | both | 1,142 KiB ± 10% |
| B9 | Harness drives Paillier | workload | acceptance passes |
| B10 | Ablations | both | three measured pairs |

A1–A3 come first because they prevent the harness from silently attributing ElGamal results to
Paillier. B0 and B1 come before any cryptography because they are the two cheapest ways to
discover the plan is wrong. **B2a comes before B3** because if the predicted cost ratios are badly
off, the sweep design changes before more is built on them.

---

## 4. The Python module

### 4.1 `helios/crypto/paillier.py` — required surface

Method signatures must match `algs.py` / `elgamal.py` exactly where a counterpart exists, so
`homomorphic.py`'s call sites need no branching.

```python
class Paillier:                                    # ≙ elgamal.Cryptosystem
  key_size: int = 1024                             # bits per prime
  def generate_keypair(self) -> PaillierKeyPair

class PaillierKeyPair:                             # ≙ elgamal.KeyPair
  pk: PaillierPublicKey
  sk: PaillierSecretKey
  def generate(self, key_size: int) -> None

class PaillierPublicKey:                           # ≙ elgamal.PublicKey
  datatype = 'paillier/PublicKey'                  # ← REQUIRED, see §5.1
  n: int
  g: int                                           # == n + 1, stored explicitly
  @property
  def n2(self) -> int                              # derived, never serialized

  # --- surface used by homomorphic.py, signature-identical to ElGamal ---
  def encrypt_with_r(self, plaintext, r, encode_message=False) -> PaillierCiphertext
  def encrypt_return_r(self, plaintext) -> list     # [ciphertext, r]
  def encrypt(self, plaintext) -> PaillierCiphertext
  def __mul__(self, other)                          # combine trustee keys: n must match; single
                                                    # trustee, so return self when other in (0, 1),
                                                    # else raise NotImplementedError
  def validate_pk_params(self) -> None               # raises, like EGPublicKey.validate_pk_params

  # --- the scheme-dispatch surface added by §4.2 ---
  def generate_plaintexts(self, min=0, max=1) -> list[PaillierPlaintext]
  def random_randomness(self) -> int
  def combine_randomness(self, acc: int, r: int) -> int
  def tally_decoder(self, num_tallied: int)          # -> Callable[[int], int]
  def verify_decryption_proof(self, ciphertext, factor, proof, challenge_generator) -> bool
  @property
  def disjunctive_challenge_generator(self)
  @property
  def ciphertext_class(self)

  def to_dict(self) -> dict ; toJSONDict = to_dict
  @classmethod
  def from_dict(cls, d) -> PaillierPublicKey ; fromJSONDict = from_dict


class PaillierSecretKey:                           # ≙ elgamal.SecretKey
  datatype = 'paillier/SecretKey'
  p: int ; q: int ; lambda_: int ; mu: int
  public_key: PaillierPublicKey
  @property
  def pk(self)                                     # alias, as elgamal.SecretKey has

  def decryption_factor(self, ciphertext) -> int   # == the plaintext m; masterplan §3.3, the seam
  def decryption_factor_and_proof(self, ciphertext, challenge_generator=None) -> tuple
  def decrypt(self, ciphertext, dec_factor=None, decode_m=False) -> PaillierPlaintext
  def decrypt_no_crt(self, ciphertext) -> int      # ablation path, §2.4
  def prove_sk(self, challenge_generator) -> None  # returns None — see §4.4


class PaillierPlaintext:                           # ≙ algs.EGPlaintext
  m: int                                           # the integer itself. NO g^m encoding.
  pk: PaillierPublicKey


class PaillierCiphertext:                          # ≙ algs.EGCiphertext
  datatype = 'paillier/Ciphertext'
  c: int
  pk: PaillierPublicKey

  def __mul__(self, other)                         # (self.c * other.c) % n2; identity on 0 and 1
  def __eq__(self, other)
  def generate_encryption_proof(self, plaintext, randomness, challenge_generator)
  def simulate_encryption_proof(self, plaintext, challenge=None)
  def generate_disjunctive_encryption_proof(self, plaintexts, real_index, randomness,
                                            challenge_generator) -> PaillierZKDisjunctiveProof
  def verify_encryption_proof(self, plaintext, proof) -> bool
  def verify_disjunctive_encryption_proof(self, plaintexts, proof, challenge_generator) -> bool
  def decrypt(self, decryption_factors, public_key) -> int     # single trustee: factors[0]
  def check_group_membership(self, pk) -> bool                 # 0 < c < n², gcd(c, n) == 1
  def to_dict(self) ; toJSONDict ; from_dict ; fromJSONDict


class PaillierZKProof:                             # ≙ algs.EGZKProof
  datatype = 'paillier/ZKProof'
  commitment: int          # a   — a scalar, NOT a {'A','B'} dict
  challenge: int           # e
  response: int            # z
  @classmethod
  def generate(cls, u, v, pk, challenge_generator) -> PaillierZKProof
  @classmethod
  def simulate(cls, u, pk, challenge=None) -> PaillierZKProof
  def verify(self, u, pk, challenge_generator=None) -> bool
  def to_dict / from_dict


class PaillierZKDisjunctiveProof:                  # ≙ algs.EGZKDisjunctiveProof
  datatype = 'paillier/ZKDisjunctiveProof'
  proofs: list[PaillierZKProof]
  def to_dict(self) -> list                        # BARE ARRAY. See §5.2.
```

Notes that are easy to get wrong:

- **`PaillierPlaintext.m` is the integer.** ElGamal's `generate_plaintexts` builds `g^0, g^1, …`
  because `ElGamal.encrypt` refuses to encrypt zero. Paillier encrypts zero natively, so
  `generate_plaintexts(min, max)` returns `PaillierPlaintext(i)` for `i in range(min, max+1)`.
- **`encode_message` is accepted and ignored.** It exists on `EGPublicKey.encrypt_with_r` for
  subgroup encoding, which has no Paillier meaning. Keep the parameter for signature parity;
  raise if it is ever passed `True`.
- **`PaillierZKProof.commitment` is a scalar.** ElGamal's is `{'A': …, 'B': …}`. This is why
  Π_root is cheaper (§5.2 of the masterplan) and it is a deliberate shape difference. Keep the
  field *name* `commitment` so `proof_bytes` slicing in the harness is unaffected.
- **`prove_sk` returns `None`** and the caller stores a null `pok`. Do not fabricate a proof
  object — an empty proof would verify vacuously. See §4.4.

### 4.2 The nine dispatch points in `homomorphic.py`

Do **not** add `if scheme == …` branches. Move the scheme-specific behaviour onto the public key
object, which `homomorphic.py` already holds in every one of these scopes. After this refactor
`homomorphic.py` contains **zero** references to `algs` or to any scheme name — that is the gate.

| # | Line | Current | Replace with |
|---|---|---|---|
| 1 | `:34` | `algs.EGPlaintext(running_product, pk)` in `generate_plaintexts` | delegate the whole classmethod body to `pk.generate_plaintexts(min, max)` |
| 2 | `:68` | `algs.EG_disjunctive_challenge_generator` (verify, individual) | `pk.disjunctive_challenge_generator` |
| 3 | `:80` | same (verify, overall) | same |
| 4 | `:128` | `algs.random.mpz_lt(pk.q)` | `pk.random_randomness()` |
| 5 | `:133` | challenge generator (encrypt, individual) | `pk.disjunctive_challenge_generator` |
| 6 | `:150` | challenge generator (encrypt, overall) | `pk.disjunctive_challenge_generator` |
| 7 | `:138` | `randomness_sum = (randomness_sum + randomness[answer_num]) % pk.q` | `randomness_sum = pk.combine_randomness(randomness_sum, randomness[answer_num])` |
| 8 | `:437` | `algs.EGCiphertext.fromJSONDict` in `Tally._process_value_in` | `pk.ciphertext_class.fromJSONDict`, with a dict-shape fallback — see below |
| 9 | `:415`, `:429` | `DLogTable(base=public_key.g, modulus=public_key.p)` and `dlog_table.lookup(raw_value)` in `decrypt_from_factors` (`:406`) | `decoder = public_key.tally_decoder(self.num_tallied)`; then `q_result.append(decoder(raw_value))` |

Plus, in `Tally.verify_decryption_proofs` (`:386`), the positional ElGamal call at `:401`

```python
proof.verify(public_key.g, answer_tally.alpha, public_key.y,
             int(decryption_factors[q_num][a_num]), public_key.p, public_key.q,
             challenge_generator)
```

becomes

```python
public_key.verify_decryption_proof(answer_tally, decryption_factors[q_num][a_num],
                                   proof, challenge_generator)
```

with the ElGamal implementation being the existing expression moved verbatim into
`elgamal.PublicKey`… **which you may not modify.** Resolve this by putting the ElGamal side in a
thin adapter — see the initial-value note below.

**`randomness_sum` initial value.** ElGamal starts it at `0` (`:110`, additive identity); Paillier
needs `1` (multiplicative identity). Add `pk.randomness_identity` as a property (ElGamal `0`,
Paillier `1`) and initialise from it. Leave `homomorphic_sum` (`:60`, `:109`) at `0` — it relies on
`EGCiphertext.__mul__` returning `self` when the other operand is `0` or `1` —
`PaillierCiphertext.__mul__` must do the same, so that one can stay as it is.

**Where the ElGamal implementations live**, given rule 2 forbids editing `algs.py` and
`elgamal.py`: create `helios/crypto/scheme_adapters.py` containing the ElGamal methods listed
above, and attach them to `elgamal.PublicKey` / `algs.EGPublicKey` at import time (a small,
explicit monkey-patch module with the bodies copied verbatim from their current call sites). This
keeps both crypto modules byte-identical while giving `homomorphic.py` one uniform interface.
Import it from `helios/workflows/__init__.py`. State this clearly in the milestone report — it is
the one place the design trades purity for the no-edit rule, and a reviewer should see it.

**`Tally._process_value_in` may run before `self.public_key` is set.** If `getattr(self,
'public_key', None)` is falsy, dispatch on the dict's field set instead: `'alpha' in a` →
ElGamal, `'c' in a` → Paillier. Cover both orderings in a test.

### 4.3 `helios/models.py`

```python
# Election
crypto_scheme = models.CharField(max_length=20, null=False, default='elgamal')
```

Migration: additive, nullable=False with a default, no data migration.

`generate_trustee(self, params)` currently hardcodes two things:

```python
trustee.public_key_hash = datatypes.LDObject.instantiate(
    trustee.public_key, datatype='legacy/EGPublicKey').hash
trustee.pok = trustee.secret_key.prove_sk(algs.DLog_challenge_generator)
```

Replace with:

```python
trustee.public_key_hash = datatypes.LDObject.instantiate(
    trustee.public_key, datatype=params.public_key_datatype).hash
trustee.pok = trustee.secret_key.prove_sk(params.dlog_challenge_generator)
```

adding `public_key_datatype` and `dlog_challenge_generator` to both `Paillier` and (via the
adapter module) `elgamal.Cryptosystem`. `Paillier.dlog_challenge_generator` is `None`, and
`PaillierSecretKey.prove_sk` returns `None` regardless — see §4.4.

### 4.4 The `pok` field

Paillier generates no trustee proof of knowledge of the secret key. Its analogue is a proof of
knowledge of the factorization (Poupard–Stern): real work, no measurement payoff.

`Trustee.pok` is `LDObjectField(type_hint='legacy/DLogProof', null=True)`, so `None` persists
cleanly. Verify that `Trustee.toJSONDict()` and the trustee page render with `pok = None` — if
`legacy.Trustee`'s `STRUCTURED_FIELDS` chokes on it, the fix is in the Paillier trustee datatype,
not in `legacy.py`.

**Do not fabricate an empty proof object.** An empty proof is a proof that verifies vacuously.

Emit the ElGamal cost for comparison: the harness already collects 30 `prove_sk_time_ns` samples
per run, so the manuscript can quantify exactly what is being omitted.

### 4.5 `helios/views.py`

```python
PAILLIER_PARAMS = paillier.Paillier()
PAILLIER_PARAMS.key_size = 1024
```

At the three `election.generate_trustee(ELGAMAL_PARAMS)` call sites (`:218`, `:417`, `:1204`),
select on `election.crypto_scheme`. Add a scheme field to `forms.ElectionForm` with `elgamal` as
the default so existing behaviour is unchanged when the field is absent.

Keep `ELGAMAL_PARAMS` and `ELGAMAL_PARAMS_LD_OBJECT` exactly as they are.

### 4.6 Enforcing the single-trustee constraint

Helios is built for **multiple** trustees, and the single-trustee restriction adopted for the
Paillier arm is not merely "we happen to add one." Three code paths actively assume the
multi-trustee model and will do the wrong thing under Paillier.

**Why the restriction is forced, not chosen.** ElGamal-Helios combines trustee keys at freeze
(`models.py:613-618`):

```python
    trustees = list(Trustee.get_by_election(self))
    combined_pk = trustees[0].public_key
    for t in trustees[1:]:
      combined_pk = combined_pk * t.public_key
    self.public_key = combined_pk
```

This works because every ElGamal trustee shares the same hardcoded `(p, q, g)`, so `y = Π yᵢ`
corresponds to a secret `x = Σ xᵢ` and no trustee knows it alone. Each trustee generates its
keypair independently in its own browser and uploads `yᵢ` with a Schnorr PoK
(`views.trustee_upload_pk:601`); the trustees never communicate. **This is not distributed key
generation** — there is no shared secret, no polynomial, no verifiable secret sharing, and the
scheme is n-of-n rather than threshold. `algs.py:530` and `elgamal.py:420` both say so:
`For now, no support for threshold`.

**Paillier has no shared group to generate into.** Trustees would produce unrelated moduli `nᵢ`,
and there is no operation that combines RSA-style moduli into a joint public key. Paillier's
multi-party counterpart is the *threshold* variant, which does require genuine DKG — a protocol
producing a shared `n` whose factorization nobody holds. That is out of scope, so single-trustee
follows from the cryptosystem's structure, not from a convenience choice.

Do not paraphrase this in the manuscript as "DKG is out of scope" — Helios has no DKG, so that
phrasing implies a Helios feature was dropped. Masterplan §11.2 carries the drafted wording.

**Four enforcement points. Implement all of them — each catches a different route in.**

1. **`PaillierPublicKey.__mul__`** — return `self` when `other` is `0` or `1` (the identity cases
   `homomorphic_sum` relies on), and otherwise raise with an explanatory message:
   `NotImplementedError("Paillier trustee keys cannot be combined; threshold Paillier requires DKG, which is out of scope. See PAILLIER_BUILD_SPEC.md §4.6.")`
   This is the last-resort guard. It fires at freeze, which is late — hence the next three.

2. **`Election.issues_before_freeze`** (`models.py:418-446`) — add an issue for a Paillier
   election with more than one trustee, so the admin is told *before* freeze rather than getting
   an exception during it. Follow the existing format, a list of `{'type': …, 'action': …}` dicts:
   `{'type': 'trustees', 'action': 'remove the extra trustees — Paillier elections support exactly one'}`.
   Helios already renders these on the election page, so no template work is needed.

3. **`views.new_trustee` (`:399`) and `views.trustee_upload_pk` (`:601`)** — refuse for an
   election whose `crypto_scheme == 'paillier'`, with a message naming the reason. These are the
   two routes by which a second trustee can be added at all. `new_trustee_helios` (`:413`) is
   fine: it creates the single Helios trustee, which is the intended one.

4. **`PaillierCiphertext.decrypt(decryption_factors, public_key)`** — `combine_decryptions`
   (`models.py:519-528`) always passes a *list* of per-trustee factor sets. Do **not** silently
   return `decryption_factors[0]`. Assert `len(decryption_factors) == 1` and raise otherwise.
   A silent `[0]` would produce a plausible-looking but wrong result if a second trustee ever
   existed, which is exactly the failure mode that reaches the results chapter unnoticed.

`Election.ready_for_decryption_combination` (`:500`) iterates all trustees and needs no change —
with one trustee it is already correct.

**Do not "fix" this by making Paillier support multiple trustees.** That is threshold Paillier,
it needs DKG, and it is out of scope. The correct behaviour is a clear refusal.

---

## 5. Datatypes

### 5.1 B0 — the dispatch spike (do this first)

**Problem.** Nine `LDObjectField` type hints are static (`models.py:69, 71, 143, 956, 1142, 1290,
1297, 1301, 1308`), so a Paillier public key stored in `Election.public_key` is handed to the
ElGamal deserializer. The reach includes `encrypted_tally` and every `CastVote.vote`, which
resolve down to `legacy/EGCiphertext` — the ballots and the tally, not just the keys.

**Approach (a) — try this first.** Two changes in `helios/datatypes/__init__.py`:

1. In `LDObject.instantiate` (`:127`), flip the precedence so the wrapped object's own `datatype`
   wins when set:

   ```python
   obj_datatype = getattr(obj, 'datatype', None)
   if obj_datatype:
       datatype = obj_datatype
   elif not datatype:
       raise Exception("no datatype found")
   ```

   This is a **no-op for ElGamal**: the wrapped `crypto_elgamal.*` classes carry no `datatype`
   attribute (`get_class` sets it on the *LDObject subclass*, not the wrapped object). Confirm
   that by assertion before relying on it.

2. In `LDObject.fromDict` (`:218-225`), resolve the type from the dict when the hint is a
   scheme-bearing one. Helios's own FIXME sits on the line:

   ```python
   # the LD type is either in d or in type_hint
   # FIXME: get this from the dictionary itself
   ld_type = type_hint
   ```

   Implement a small registry: `{'alpha','beta'} ⊂ d.keys()` → ElGamal; `{'c'} ⊂ d.keys()` →
   Paillier; and likewise `{'y','p','g','q'}` vs `{'n','g'}` for public keys, `{'x'}` vs
   `{'p','q','lambda','mu'}` for secret keys, `commitment` being a dict vs a string for proofs.
   Apply the registry **only** when `type_hint` names one of the six ambiguous legacy datatypes;
   pass everything else straight through.

**Gate.** All of:

- A dummy non-ElGamal object with `datatype = 'paillier/…'` round-trips through an
  `LDObjectField` — save, reload, compare.
- The full upstream test suite passes unchanged.
- `BigInteger(0).toDict() == "0"` (§1.3 fix applied).
- Every call site of `LDObject.instantiate` audited and listed in the report, with a note on each
  saying why the precedence flip is safe there.

**If the gate is red**, stop and report. The fallback is approach (b): parallel nullable columns
`paillier_public_key` / `paillier_secret_key` plus branches at each read site. It is uglier and
costs a migration; do not adopt it without saying so.

### 5.2 `helios/datatypes/paillier.py`

Mirror `legacy.py`'s structure. **Every field must appear in `STRUCTURED_FIELDS`** (§1.4).

```python
from helios.datatypes import LDObject, arrayOf
from helios.crypto import paillier as crypto_paillier

class PaillierObject(LDObject):
    WRAPPED_OBJ_CLASS = dict
    USE_JSON_LD = False

class PublicKey(PaillierObject):
    WRAPPED_OBJ_CLASS = crypto_paillier.PaillierPublicKey
    FIELDS = ['n', 'g']
    STRUCTURED_FIELDS = {'n': 'core/BigInteger', 'g': 'core/BigInteger'}

class SecretKey(PaillierObject):
    WRAPPED_OBJ_CLASS = crypto_paillier.PaillierSecretKey
    FIELDS = ['public_key', 'p', 'q', 'lambda_', 'mu']
    STRUCTURED_FIELDS = {'public_key': 'paillier/PublicKey',
                         'p': 'core/BigInteger', 'q': 'core/BigInteger',
                         'lambda_': 'core/BigInteger', 'mu': 'core/BigInteger'}

class Ciphertext(PaillierObject):
    WRAPPED_OBJ_CLASS = crypto_paillier.PaillierCiphertext
    FIELDS = ['c']
    STRUCTURED_FIELDS = {'c': 'core/BigInteger'}

class ZKProof(PaillierObject):
    WRAPPED_OBJ_CLASS = crypto_paillier.PaillierZKProof
    FIELDS = ['commitment', 'challenge', 'response']
    STRUCTURED_FIELDS = {'commitment': 'core/BigInteger',
                         'challenge': 'core/BigInteger',
                         'response': 'core/BigInteger'}

class ZKDisjunctiveProof(PaillierObject):
    WRAPPED_OBJ_CLASS = crypto_paillier.PaillierZKDisjunctiveProof
    FIELDS = ['proofs']
    STRUCTURED_FIELDS = {'proofs': arrayOf('paillier/ZKProof')}

    def loadDataFromDict(self, d):
        return super().loadDataFromDict({'proofs': d})

    def toDict(self, complete=False):
        return super().toDict(complete=complete)['proofs']
```

The `loadDataFromDict` / `toDict` override on `ZKDisjunctiveProof` is **not optional**. It copies
`legacy.EGZKDisjunctiveProof`, which serializes as a bare array rather than a wrapping object. Get
this wrong and `individual_proofs` changes shape, which silently breaks the harness's
`proof_bytes` slice (§8).

The `lambda_` field name avoids the Python keyword; serialize it as `"lambda"` by overriding
`process_value_out`/`process_value_in`, or name the attribute `lambda_` and the JSON key
`lambda_` consistently — pick one, write it down in the report, and never mix them.

### 5.3 Serialization schema — normative

```jsonc
// ciphertext
{"c": "<decimal, 0 ≤ c < n²>"}

// one Π_root transcript
{"commitment": "<decimal a>", "challenge": "<decimal e>", "response": "<decimal z>"}

// disjunctive proof — a BARE ARRAY
[ {...}, {...} ]

// encrypted answer — OUTER NAMES IDENTICAL TO ELGAMAL
{"choices":           [ {"c": "..."} , ... ],
 "individual_proofs": [ [ {...}, {...} ], ... ],
 "overall_proof":     [ {...}, ... ]}

// public key
{"n": "<decimal>", "g": "<decimal, == n+1>"}
```

All big integers are **decimal strings**, matching `EGCiphertext.to_dict`'s `str(self.alpha)`.
Never hex, never base64 — it would change measured ballot size and break comparability with the
ElGamal baseline.

`g` is serialized even though it equals `n+1`: it costs nothing, mirrors `EGPublicKey`'s redundant
four fields, and gives `validate_pk_params` something to check.

Produce a worked fixture at B2 — a real ballot for a 2-question, 3-candidate face under a
64-bit-prime toy key, committed as `helios/fixtures/paillier_ballot_toy.json` — so later
milestones have something concrete to diff against.

---

## 6. The JavaScript side

### 6.1 B1 — cross-language challenge agreement (before anything else)

The cheapest possible de-risking of the whole build. One hour, and it removes the failure mode
where every ballot verifies locally and every cast fails.

Fixture `helios/fixtures/challenge_vectors.json`: at least 12 cases, covering L = 1, 2, 13; values
spanning 1 digit to 1234 digits; a value with a leading digit of 1 and one with 9; `a = 1`.

```json
[{"commitments": ["1"], "challenge": "<decimal>"},
 {"commitments": ["1","2"], "challenge": "..."},
 {"commitments": ["<1234-digit>", "..."], "challenge": "..."}]
```

Generate the expected values with the Python implementation from §2.9, then assert the JS
implementation reproduces every one, under Node and in the browser.

**Gate:** all vectors agree in Python, in Node, and in Chrome. Any mismatch stops the build until
resolved — do not proceed and "fix it later."

### 6.2 `heliosbooth/js/jscrypto/paillier.js`

Structure it as a mirror of `elgamal.js`, which is a proven template:

```
Paillier.PublicKey            init(n, g); toJSONObject; fromJSONObject; encrypt(plaintext, r)
Paillier.Plaintext            init(m, pk)                     // m is the integer; no encoding
Paillier.Ciphertext           init(c, pk); multiply; toJSONObject; fromJSONObject
                              generateProof / simulateProof / verifyProof
                              generateDisjunctiveProof / verifyDisjunctiveProof
Paillier.Proof                init(a, challenge, response); toJSONObject; fromJSONObject; verify
Paillier.Proof.generate(u, v, pk, challenge_generator)
Paillier.Proof.simulate(u, pk, challenge)
Paillier.DisjunctiveProof     init(list_of_proofs); toJSONObject   // bare array
Paillier.disjunctive_challenge_generator / fiatshamir_challenge_generator     // §2.9
```

`generateDisjunctiveProof(list_of_plaintexts, real_index, randomness, challenge_generator)` keeps
ElGamal's exact signature and closure structure, so `helios.js` needs no branching beyond
selecting the scheme.

**Starting point:** `mhe/jspaillier` (MIT, 98 lines, jsbn-based) already implements keygen,
encrypt and decrypt with the `(1+n)^m = 1+mn` shortcut in the correct form. You may copy it, and
you must then: swap its `SecureRandom` for `Random.getRandomInteger`, add the `toJSONObject` /
`fromJSONObject` conventions from `bigint.js`, and drop its keygen (the booth never generates
keys). Record the attribution and its MIT licence in a header comment.

**jsbn traps:**

- Helios's jsbn is **modified** — limbs are `this.arr[i]`, not `this[i]`. The public API is
  unchanged, so code written against the standard `BigInteger` surface works untouched, but you
  cannot drop in npm `jsbn` alongside it and you cannot lift internal-touching code from
  elsewhere. **Depend only on public methods**: `modPow`, `modInverse`, `multiply`, `mod`, `gcd`,
  `add`, `subtract`, `equals`, `compareTo`, `shiftLeft`, `toString`.
- `bigint.js` aliases `BigInt = BigInteger` and defines `toJSONObject()` → `toString()` and
  `BigInt.fromJSONObject(s)` → `new BigInt(s, 10)`. Every serialized value must go through these.
- There is **no native `BigInt`** in this code path and there must not be. Using it would make
  Paillier faster for reasons that have nothing to do with Paillier and would invalidate the
  comparison.

### 6.3 `heliosbooth/js/jscrypto/helios.js`

Two functions become scheme-aware. Dispatch on the public key object's type, not on a string.

`UTILS.generate_plaintexts(pk, min, max)` (`:193`) currently builds `g^i` by repeated
multiplication. Give it a scheme branch, or better, move the body onto the public key
(`pk.generatePlaintexts(min, max)`) to mirror §4.2's Python approach.

`HELIOS.EncryptedAnswer.doEncryption` (`:236`) hardcodes three things:

```javascript
randomness[i] = Random.getRandomInteger(pk.q);                          // :273
choices[i] = ElGamal.encrypt(pk, zero_one_plaintexts[plaintext_index], randomness[i]);  // :276
individual_proofs[i] = choices[i].generateDisjunctiveProof(..., ElGamal.disjunctive_challenge_generator);  // :281
```

plus `rand_sum = rand_sum.add(randomness[i]).mod(pk.q)` in the overall-proof block. Route all four
through the public key, exactly as §4.2 does on the Python side. `rand_sum` starts at
`randomness[0]` for ElGamal; for Paillier it starts at `randomness[0]` too and combines by
multiplication mod n — put that behind `pk.combineRandomness(acc, r)`.

### 6.4 B6 — bundle and worker

Both loaders, or nothing works consistently (§1.6):

1. `heliosbooth/boothworker-single.js` — add `"js/jscrypto/paillier.js"` to `importScripts`,
   after `elgamal.js` and before `helios.js`.
2. `heliosbooth/vote.html` — add the commented-out `<script>` line for symmetry, then rebuild the
   compressed bundle per `build-helios-booth-compressed.txt` and update the `<script src>` to the
   new filename. Keep the old bundle in the tree.

**Gate:** `HELIOS.EncryptedAnswer` produces a Paillier ballot both (a) on the main thread from
`/booth/vote.html`, which is what the harness drives, and (b) inside the worker, which is what a
real voter uses. Assert both produce structurally identical output for a fixed key.

---

## 7. Tests

`helios/tests_paillier.py`. Tests 1–4 are the manuscript's; 5–16 are additions the manuscript
should have listed. Use small keys (`p = 1019, q = 1031` and similar) everywhere except tests
explicitly marked full-size, so the suite runs in seconds.

| # | Test | Setup | Passes when |
|---|---|---|---|
| 1 | Decryption correctness | m ∈ {0, 1, 2, 10⁶} and n−1 | `Dec(Enc(m)) == m` on **both** the CRT and non-CRT paths |
| 2 | Homomorphic addition | m₁+m₂ < n | `Dec(Enc(m₁)·Enc(m₂) mod n²) == m₁+m₂` |
| 3 | End-to-end tally | Known votes, smoke face | Per-slot tally equals the plaintext sum |
| 4 | Schema conformance | Every datatype in §5.2 | Round-trips through `LDObject` unchanged; decimal strings only; disjunctive proof is a bare array |
| 5 | Individual-proof soundness | Ciphertext of 2, proved as 0/1 | Verification **fails** |
| 6 | Overall-proof soundness | 13 selections in a max-12 question | Verification **fails** |
| 7 | Completeness | 1,000 honest proofs, L ∈ {2, 13} | All verify |
| 8 | Decryption-proof soundness | Proof for a wrong `m` | Verification **fails** |
| 9 | **Cross-implementation** | Every proof type, both directions | JS-generated verifies in Python and vice versa |
| 10 | **Special-soundness extraction** | Fixed commitment, two challenges (§2.5) | Extracted `v` satisfies `v^n ≡ u (mod n²)` |
| 11 | **Response distribution** | ≥1,000 proofs; bit lengths of real vs simulated `z` | Means within 1 bit; two-sample KS test does not reject at α=0.01. **The `ishaq` canary.** |
| 12 | **Tamper matrix** | Perturb each of `a`, `e`, `z`, `u_j` independently; permute the real index | Every perturbation **fails** |
| 13 | **CRT agreement** | Same ciphertexts, both paths; `h_p` both ways | Identical results (§2.4) |
| 14 | **Oracle agreement** | Fixed `(p, q, m, v)` vs `phe` | Identical ciphertexts and plaintexts |
| 15 | **ElGamal golden ballot** | Fixed seed and key, baseline captured **before** any change | Byte-identical serialization |
| 16 | **Single-trustee enforcement** | All four routes in §4.6: `__mul__` with a second key; a two-trustee Paillier election at `issues_before_freeze`; `new_trustee` and `trustee_upload_pk` on a Paillier election; `decrypt` with two factor sets | Each **refuses**, with the §4.6 message. A two-trustee **ElGamal** election still freezes and tallies normally |

**Capture the test-15 baseline before touching anything.** Commit it at B0. It is the only thing
that proves the §4.2 refactor left the ElGamal path alone, and it cannot be reconstructed after
the fact.

Test 11 needs care: compare the *distributions*, not individual values. The `ishaq` bug shows up
as a real branch averaging ~2× the bit length of simulated ones, so a mean-difference assertion
catches it, and a KS test catches subtler variants.

Test 9 depends on B1's fixtures plus a Node harness that loads the booth's `jscrypto/*.js` — a
handful of browser globals need shimming. Keep that shim in `helios/tests/js_bridge/`, not in
`heliosbooth/`.

---

## 8. Harness changes (workload repo)

These gate B9, and A1 gates the whole build.

### 8.1 A1 — the scheme guard

Today, `python runner.py --scheme paillier --n 10 --skip keygen` runs a complete **ElGamal**
election, stamps `"scheme":"paillier"` on all ~71 emitted records, and **passes acceptance**,
because `acceptance.py` never reads `r['scheme']`. Only `drivers/stage1_freeze.py:41` branches on
scheme, and `runner.py:94` lets you skip it.

Two changes:

1. `runner.py` — a registry of supported schemes and their driver sets. Refuse to start when the
   requested scheme has no registered driver, **regardless of `--skip`**. `--skip` must never be
   able to route around the scheme gate.
2. `acceptance.py` — a check that cross-references the emitted `scheme` against something only
   that scheme could have produced: the shape of the persisted ballot (`alpha`/`beta` vs `c`), or
   the election's `crypto_scheme` read back from the database.

While you are in `runner.py`, fix the dead `--skip 2`: `:265` advertises `keygen,2`, `:283` keys
on `'2a'`, and the Stage 2 block at `:126-179` has no gate at all. Either implement it or remove
it from the help text.

**Gate:** `--scheme paillier` fails loudly before B7, and passes after; `--scheme elgamal`
behaves exactly as it does today.

### 8.2 A2 — scheme-aware Stage 4

`drivers/stage4_decrypt.py` unconditionally imports `DLogTable` and constructs it at `:67` from
`pk.g` and `pk.p`, which a Paillier public key does not have. `lookup_ns = max(t_combine.ns -
t_precompute.ns, 0)` then collapses to the whole combine time and is emitted as
`dlog_lookup_time_ns` (`runner.py:225-229`).

Emit the dlog metrics only for ElGamal. For Paillier emit `decryption_time_ns` as a single
measurement. Do not emit a zero — an absent metric is honest, a zero is a claim.

### 8.3 A3 — acceptance

`acceptance.py:23-33` lists `dlog_precompute_time_ns` and `dlog_lookup_time_ns` in
`REQUIRED_METRICS`, and `:164-169` **fails** when precompute time is zero — the correct value for
Paillier. Make the required-metric set scheme-dependent.

While there: `:162` carries the comment "~13 µs each (§0.1)". That constant was superseded —
`claude/run_analysis_n10.md` §2.1 gives ~23.8 µs and the N=1000 run gives 26.0 µs. Fix the
comment. Same figure appears in `notes/paillier_dlog_hypothesis_verification.md`.

### 8.4 B9 — driving Paillier

`stage0_configure.py` POSTs to `/helios/elections/new` with no scheme parameter, so the election's
keypair is ElGamal regardless of `--scheme`. Add the scheme to the form post and thread it
through. `stage2_encryption.py` needs no change if §5.3's outer field names are kept — verify that
rather than assuming it, because `JSON.stringify(undefined)` encodes to the nine bytes
`"undefined"` with no exception, which would show up as a plausible-looking `ciphertext_bytes: 9`.

---

## 9. B2a — the microbenchmark

The masterplan's §5 cost model predicts encryption at **13.7×** and CRT decryption at **6.2×**
ElGamal, and those numbers currently rest on a derivation, not a measurement. They drive the sweep
design and one manuscript conclusion, so measure them before building further.

A standalone script, `helios/benchmarks/modexp_bench.py`, timing with `time.perf_counter_ns`,
≥30 samples each, reporting median and IQR:

| Operation | Modulus | Exponent |
|---|---|---|
| ElGamal encrypt path | 2048-bit `p` | 256-bit (`< q`) |
| Paillier `v^n` | 4096-bit `n²` | 2048-bit `n` |
| Paillier CRT half | 2048-bit `p²` | 1024-bit `p−1` |
| Π_root response `v^e` | 2048-bit `n` | 160-bit |

Then the same four in the browser under jsbn, via a small page the harness's Selenium driver can
load — the booth's cost is what the thesis measures, and CPython's ratios need not match jsbn's.

**Report the measured ratios against the predicted 13.7× / 6.2× / 3.9×.** If they differ by more
than ~25%, stop and report before B3: the sweep design and one manuscript conclusion depend on
them.

---

## 10. Reporting

At each gate, report:

- Which gate, and pass or fail.
- Files added and files modified, with a one-line reason each.
- Confirmation that `algs.py` and `elgamal.py` are untouched (`git diff --stat` on both).
- Tests added and their results.
- Anything you found that contradicts this document or the masterplan. **These two documents have
  been wrong before** — the old spec pointed at the wrong module, assumed the wrong class surface,
  used the wrong challenge width, and carried a cost model with an eight-fold unit error. If the
  code disagrees with the document, the code is right and the document needs fixing. Say so.

Do not proceed past a red gate. Do not "temporarily" disable a failing test.

---

## 11. References

- Damgård, Jurik, Nielsen, *A Generalization of Paillier's Public-Key System with Applications to
  Electronic Voting*, IJIS 9(6):371–385, 2010 — §3.2 (`g = n+1`), §4.2 (CRT, one sentence only),
  §5.1 (decryption proof), §5.2 (Π_root and 1-out-of-2), §6 (voting construction).
- Cramer, Damgård, Schoenmakers, CRYPTO 1994 — the general 1-out-of-L composition. **Cite this,
  not DJN, for L > 2.**
- `mhe/jspaillier` — MIT, jsbn-based, the JS starting point.
- `data61/python-paillier` (`phe`) — **GPLv3, test oracle only. Never copy into the source tree.**
- `lovesh/generalized_paillier` — Apache-2.0 Rust; best algorithmic reference for §2.4's CRT.
- `ishaq/Paillier-E-Voting` — unlicensed, and **broken** in the way §2.5 warns about. Read it to
  understand the failure, never to copy.
- `PAILLIER_MASTERPLAN.md` — goals, findings, decisions, risks, sequencing, and the draft §9.2.3.