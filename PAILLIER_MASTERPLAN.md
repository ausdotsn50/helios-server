# Paillier-Helios: masterplan

**Scope.** Objective 1 — *"To implement a modified Helios prototype integrating the Paillier
cryptosystem in place of Exponential ElGamal."* This document is self-contained: it sets goals,
specifies the cryptography completely, fixes every design decision, lists the vetted resources,
and sequences the work. It is the sole input to the build specification. §11 is drafted as
manuscript prose to close the §9.2.3 TBD.

**Codebase at time of writing** (read directly, 2026-09-05):

```
helios-server   HEAD d61eaa8 "milestone-1 (#1)"  → parent c7d5e60 (the manuscript-pinned commit)
                dirty: pyproject.toml, uv.lock
workload        HEAD 1edd9b4, 9 modified/untracked paths; last run stamped 4a87fce
                8 result sets from 2026-09-04, all ElGamal
```

**Relationship to the other documents.** This supersedes `IMPLEMENTATION_SPEC.md` Part 2
entirely — its cryptography is reproduced and corrected in §4, its file map was wrong for this
checkout (§2.1), and two of its parameter choices are reversed (§6). It also **supersedes
`claude/implementation_parity_defense.md` §4.2**, whose cost model contains an arithmetic error
that inverts one of its conclusions (§5.1). The parity *principle* from that document stands
unchanged and is adopted in §6. `claude/pivot_map.md` §12 supplies the sequencing constraint.

---

## 1. Goals

Objective 1 is met when all five hold, in an order where each is verifiable before the next is
attempted.

1. **A Paillier election completes end-to-end through Helios's own web flow** — created, frozen,
   voted in the browser booth, cast, verified, tallied, decrypted — with a correct result, and
   with no step bypassing the HTTP layer an ElGamal election goes through.
2. **The ElGamal path is provably unchanged.** Upstream tests pass unmodified; an ElGamal ballot
   serializes byte-identically to a pre-change baseline for a fixed seed and key.
3. **The proofs are sound, not merely fast.** Every negative test in §9.2 fails as it should and
   special-soundness extraction succeeds. A Paillier-Helios that benchmarks well and proves
   nothing is worth nothing.
4. **Python and JavaScript agree** on every proof type, both directions.
5. **The harness can drive it honestly** — a `--scheme paillier` run measures Paillier, emits
   metrics whose names mean what they say, and passes acceptance. §2.6 shows this is not
   currently true and is not a small fix.

Non-goal, stated so it does not creep in: **the Paillier variant runs exactly one trustee — the
Helios server — and threshold Paillier with distributed key generation stays out of scope.** Word
this carefully in the manuscript (§11.2): Helios itself has no DKG, so "DKG is out of scope" would
wrongly imply a Helios feature was dropped. §4.1 gives the structural reason the restriction is
forced rather than chosen; §4.7 shows it is also what makes the decryption proof tractable, which
turns the limitation into a design justification.

---

## 2. Findings that change the plan

From reading the checkout, not the manuscript. Each invalidates something currently written down.

### 2.1 The file map in `IMPLEMENTATION_SPEC.md` §2.3 is wrong

The spec places `EncryptedAnswer`, `EncryptedVote`, `Tally` and `DLogTable` in
`helios/crypto/electionalgs.py`. In this checkout they are in **`helios/workflows/homomorphic.py`**
(442 lines). `electionalgs.py` still holds same-named classes, but they are the pre-2011
`HeliosObject` lineage and nothing imports them except `helios/tests.py`, for
`one_question_winner` only.

A build agent working from the spec would edit dead code and see no effect — a day lost before
anyone notices.

### 2.2 There are two ElGamal implementations, and the one you would naturally mirror is not the one the database uses

The subtlest thing in the codebase, and it will produce a confusing class of bug if not
understood before any code is written.

- **`helios/crypto/algs.py`** (711 lines): `ElGamal`, `EGPublicKey`, `EGSecretKey`,
  `EGCiphertext`, `EGZKProof`, `EGZKDisjunctiveProof`, `DLogProof`, three challenge generators.
- **`helios/crypto/elgamal.py`** (515 lines): `Cryptosystem`, `PublicKey`, `SecretKey`,
  `Ciphertext`, `ZKProof`, `ZKDisjunctiveProof`, `DLogProof`. Its own header calls it *"a copy of
  algs.py now made more El-Gamal specific in naming, for modularity purposes."*

Near-duplicates that have drifted. The split matters because of who uses which:

| Consumer | Uses |
|---|---|
| `helios/datatypes/legacy.py` — every `WRAPPED_OBJ_CLASS` | `crypto_elgamal.*` (`elgamal.py`) |
| `helios/models.py` — `generate_trustee`, `verify_decryption_proofs` | `algs.*` |
| `helios/workflows/homomorphic.py` — the tallying algorithms | `algs.*` |
| `helios/views.py` — `ELGAMAL_PARAMS` | `elgamal.Cryptosystem` |

At runtime an election's `public_key` deserializes into a `helios.crypto.elgamal.PublicKey`;
`homomorphic.py` calls `pk.encrypt_with_r(...)` on it, getting a `helios.crypto.elgamal.Ciphertext`
back, while in the same function building plaintexts as `algs.EGPlaintext` and hashing with
`algs.EG_disjunctive_challenge_generator`. Objects from both lineages coexist in one ballot
construction, and it works only because they are duck-type compatible.

That it is already half-broken is visible: `Tally._process_value_in` calls
`algs.EGCiphertext.fromJSONDict`, while `elgamal.Ciphertext.from_string` calls a `cls.from_dict`
that does not exist on that class.

**Consequence.** "Mirror `algs.py`'s class surface" is insufficient: a Paillier module mirroring
only `algs.py` is never instantiated by the datatypes layer, and one mirroring only `elgamal.py`
does not satisfy `homomorphic.py`'s module-level calls. Write **one** `helios/crypto/paillier.py`
carrying the whole surface, point the new datatypes' `WRAPPED_OBJ_CLASS` at it, and resolve
`homomorphic.py`'s seven module-level references as in §3.2.

### 2.3 Helios already has the seam. It is `Election.datatype`, not a new field

`IMPLEMENTATION_SPEC.md` §1.3 proposes adding `Election.crypto_scheme`. Before doing that, note
what exists (`helios/models.py:52-55`):

```python
  # keep track of the type and version of election, which will help dispatch to the right
  # code, both for crypto and serialization
  datatype = models.CharField(max_length=250, null=False, default="legacy/Election")
```

`Voter.datatype` and `CastVote.datatype` derive from it by string replacement
(`models.py:1062, 1171`), and `datatypes.get_class()` resolves `"legacy/EGPublicKey"` by dynamic
import. The `helios/datatypes/` tree already carries three families — `legacy`, `2011/01`,
`pkc/elgamal` — so the mechanism is used, not aspirational.

This is Helios's own answer to hosting more than one crypto version in one server. Riding it
rather than inventing a parallel switch is the stronger position to defend: the substitution uses
an extension point the system already had.

### 2.4 …but the `LDObjectField` type hints are static, and that is the real integration problem

The seam does not reach far enough alone. Nine persisted fields hardcode their datatype at
class-definition time:

```python
helios/models.py:69    Election.public_key        'legacy/EGPublicKey'
helios/models.py:71    Election.private_key       'legacy/EGSecretKey'
helios/models.py:143   Election.encrypted_tally   'legacy/Tally'         → arrayOf(arrayOf('legacy/EGCiphertext'))
helios/models.py:956   CastVote.vote              'legacy/EncryptedVote' → EncryptedAnswer → 'legacy/EGCiphertext'
helios/models.py:1142  (second CastVote model)    'legacy/EncryptedVote'
helios/models.py:1290  Trustee.public_key         'legacy/EGPublicKey'
helios/models.py:1297  Trustee.secret_key         'legacy/EGSecretKey'
helios/models.py:1301  Trustee.pok                'legacy/DLogProof'
helios/models.py:1308  Trustee.decryption_proofs  arrayOf(arrayOf('legacy/EGZKProof'))
```

`LDObjectField.from_db_value` passes `self.type_hint` into `LDObject.fromDict`, so a Paillier
public key stored in `Election.public_key` is handed to the ElGamal deserializer. There is no
per-row dispatch. The reach is wider than the keys: `encrypted_tally` and every `CastVote.vote`
resolve down to `legacy/EGCiphertext`, so **the ballots and the tally are affected too**.

One field is already fine: `Trustee.decryption_factors` is `arrayOf(arrayOf('core/BigInteger'))`,
and a Paillier decryption factor *is* a big integer (§3.3). No change needed.

**Three ways through.**

**(a) Let the wrapped object declare its own datatype.** `LDObject.instantiate` reads
`obj.datatype` only when no explicit datatype is passed (`datatypes/__init__.py:127`):

```python
if hasattr(obj, 'datatype') and not datatype:
    datatype = getattr(obj, 'datatype')
```

Flipping that precedence — object's own `datatype` wins when set — is a **no-op for ElGamal**,
because the wrapped `crypto_elgamal.*` classes carry no `datatype` attribute (`get_class` sets it
on the *LDObject* subclass, not the wrapped one). Paillier classes set
`datatype = 'paillier/PublicKey'` on themselves and route correctly.

On the read side, `fromDict` needs a matching dispatch on the serialized dict's field set
(`alpha`/`beta` → ElGamal, `c` → Paillier). Helios's own source anticipates this — the FIXME sits
on the exact line that must change (`datatypes/__init__.py:218-225`):

```python
    def fromDict(cls, d, type_hint=None):
        ...
        # the LD type is either in d or in type_hint
        # FIXME: get this from the dictionary itself
        ld_type = type_hint
```

Cost: no migration, no schema change, no touch to any stored ElGamal representation. Risk: the
precedence flip needs every `instantiate` call site audited — a half-day spike, and the **first
task of the build**, before any crypto is written.

**(b) Parallel nullable columns** — `paillier_public_key`, `paillier_secret_key`, with a
`crypto_scheme` discriminator. Purely additive, unambiguous, costs a migration, leaves two
half-used field sets and a branch at every read site.

**(c) A full `paillier/` datatype family plus `Election.datatype = 'paillier/Election'`.** Most
idiomatic, requires duplicating ~fifteen datatype classes, and **still does not fix the static
type hints**. It solves the wrong half.

**Recommendation: (a), with a `crypto_scheme` CharField added anyway** — not for dispatch, but so
the scheme is queryable, appears in the election record, and gives the harness something to
assert against (§2.6). Confirm with the spike; fall back to (b) if the audit finds breakage.

### 2.5 The booth runs a compiled bundle; the Web Worker does not

`heliosbooth/vote.html` has every individual `<script>` tag **commented out** and loads one
concatenated file:

```html
<!--  <script language="javascript" src="js/jscrypto/elgamal.js"></script> ... -->
  <script language="javascript" src="js/20160507-helios-booth-compressed.js"></script>
```

`heliosbooth/boothworker-single.js` instead `importScripts` the individual files by name.

Two loaders; adding `paillier.js` to one and not the other fails silently. It matters especially
because of which one the harness uses: `stage2_encryption.py` loads `/booth/vote.html` and calls
`HELIOS.EncryptedAnswer` on the main thread — **the harness measures the bundle**, while a real
voter's encryption runs in the worker off the individual files. Both must be updated,
`build-helios-booth-compressed.txt` gives the recipe, and the rebuild becomes a build step.

Also a methodology note worth recording: the harness's main-thread path and the booth's worker
path execute the same source but not the same file.

### 2.6 The harness will report Paillier numbers for an ElGamal election, today

Of five stage drivers, **one** branches on scheme — `drivers/stage1_freeze.py:41`, raising
`NotImplementedError` for anything but `elgamal`. `configure`, `sample_encryptions`, `aggregate`
and `decrypt` take no `scheme` argument at all. Meanwhile `runner.py:94` gates keygen behind
`if 'keygen' not in skip:`.

So:

```
python runner.py --scheme paillier --n 10 --skip keygen
```

runs a complete ElGamal election, stamps `"scheme":"paillier"` on all ~71 records, names the
election `wl-paillier-n10-r0-xxxx`, and **passes acceptance**, because `acceptance.py` never reads
`r['scheme']`. This is the highest-risk item in the project and it should close before Paillier
work starts.

Three further harness items bear directly on Objective 1:

- **Ballot sizing is ElGamal-shaped by field name.** `stage2_encryption.py:68` computes
  `ciphertext_bytes` as `JSON.stringify(json.choices)`. A differently-keyed Paillier answer would
  make `JSON.stringify(undefined)` return `undefined`, which `TextEncoder.encode` turns into the
  nine bytes of the string `"undefined"` — no exception. §4.10's rule (keep the outer field
  names) removes the hazard rather than papering over it.
- **The dlog metrics are emitted unconditionally.** `stage4_decrypt.py:67` builds
  `DLogTable(base=pk.g, modulus=pk.p)` by direct reference to ElGamal attributes, and
  `runner.py:225-229` always emits `dlog_precompute_time_ns` and `dlog_lookup_time_ns`. Under
  Paillier, `lookup_ns = max(t_combine.ns - t_precompute.ns, 0)` collapses to the whole combine
  time and is published as "dlog lookup".
- **Acceptance would fail a correct Paillier run.** `acceptance.py:23-33` lists both dlog metrics
  as `REQUIRED_METRICS`, and `:164-169` fails when precompute time is zero — the right answer for
  Paillier.

None of this is Objective 1 work; all of it is on Objective 1's critical path. §10 sequences it.

### 2.7 Smaller corrections for the manuscript

- **Table 2's version hash.** `c7d5e60` is real, but the working tree is `d61eaa8` plus
  uncommitted `pyproject.toml`/`uv.lock` changes, and every result record already carries
  `helios_dirty: true`. Record the fork and commit actually used, and commit the dependency
  changes before any measured run, or the provenance field is decorative.
- **`ElGamal.encrypt` refuses to encrypt zero** (`elgamal.js`: `throw "Can't encrypt 0 with El
  Gamal"`), which is why votes are encoded `g^0`/`g^1`. Paillier encrypts 0 natively. This is the
  reason `generate_plaintexts` exists and must become scheme-aware.
- **The superseded dlog constant is still in the harness.** `acceptance.py:162` carries the
  comment *"~13 µs each (§0.1)"* and `notes/paillier_dlog_hypothesis_verification.md` argues from
  the same figure. `claude/run_analysis_n10.md` §2.1 corrected it to ~23.8 µs; the N=1000 run
  gives 26.0 µs. Comments only, not logic — but correct both before citing either.
- **`Trustee.verify_decryption_proofs`** (`models.py:1354`) is deeply ElGamal-shaped, passing
  `public_key.g, answer_tally.alpha, public_key.y` positionally into `proof.verify`. Not on the
  measured path, but on the *verifiability* path: leaving it un-ported gives a Paillier election
  whose decryption proofs no trustee page can check.

---

## 3. The controlled-substitution boundary

### 3.1 Replaced, branched, untouched

**Replaced — new files only:**

| New file | Contents |
|---|---|
| `helios/crypto/paillier.py` | Everything in §4.1–§4.9 |
| `helios/datatypes/paillier.py` | LDObject wrappers mirroring the `legacy/EG*` set |
| `heliosbooth/js/jscrypto/paillier.js` | Browser twin |
| `helios/tests_paillier.py` | The suite in §9.2 |

**Branched — additive changes only:**

| File | Change |
|---|---|
| `helios/workflows/homomorphic.py` | Seven `algs.*` references become scheme-dispatched (§3.2). No change to control flow, loop structure, or operation order. |
| `helios/models.py` | `generate_trustee` takes datatype and challenge generator from the cryptosystem instead of hardcoding `'legacy/EGPublicKey'` and `algs.DLog_challenge_generator`; `verify_decryption_proofs` dispatches |
| `helios/datatypes/__init__.py` | The `instantiate` precedence flip and `fromDict` dispatch (§2.4a) |
| `helios/views.py` | `PAILLIER_PARAMS`; scheme selection at election creation |
| `heliosbooth/js/jscrypto/helios.js` | `UTILS.generate_plaintexts` and `EncryptedAnswer.doEncryption` dispatch on the public key's type |
| `boothworker-single.js`, `vote.html` + rebuilt bundle | Load `paillier.js` (§2.5) |
| migration | `Election.crypto_scheme` (CharField, default `'elgamal'`) |

**Must not move.** Election creation, freeze, the voter/credential flow, `/cast` and
`/cast_confirm`, the bulletin board, `Tally.add_vote`/`add_vote_batch` control flow, the
`helios_trustee_decrypt` → `combine_decryptions` → `result` call graph, the decimal-string JSON
convention, and every line of `algs.py` and `elgamal.py`.

### 3.2 Making `homomorphic.py` scheme-agnostic without changing what it does

`homomorphic.py` names `algs` in seven places, all scheme-specific:

```
:34   algs.EGPlaintext(running_product, pk)            EncryptedAnswer.generate_plaintexts
:68   algs.EG_disjunctive_challenge_generator          verify — individual
:80   algs.EG_disjunctive_challenge_generator          verify — overall
:128  algs.random.mpz_lt(pk.q)                         fromElectionAndAnswer — randomness
:133  algs.EG_disjunctive_challenge_generator          fromElectionAndAnswer — individual
:150  algs.EG_disjunctive_challenge_generator          fromElectionAndAnswer — overall
:437  algs.EGCiphertext.fromJSONDict                   Tally._process_value_in
```

The minimal change that removes every one is to **move the scheme-specific behaviour onto the
public key object**, which `homomorphic.py` already holds in each of these scopes:

| New method on the public key | ElGamal | Paillier |
|---|---|---|
| `generate_plaintexts(min, max)` | `EGPlaintext(g^i)` for i in range | `PaillierPlaintext(i)` for i in range |
| `random_randomness()` | `random.mpz_lt(q)` | uniform in `Z*_n` |
| `disjunctive_challenge_generator` | SHA-1 over `A,B` pairs | §4.9 |
| `combine_randomness(a, b)` | `(a + b) % q` | `(a * b) % n` |
| `ciphertext_class` | `EGCiphertext` | `PaillierCiphertext` |

A mechanical refactor with an exactly-preserved ElGamal path — the ElGamal method bodies are the
existing code moved verbatim. It leaves the workflow file with **zero** scheme references, which
is what makes the identical-pipeline claim inspectable rather than argued.

`combine_randomness` deserves note: ElGamal sums randomness (`randomness_sum = (randomness_sum + r) % pk.q`),
Paillier multiplies it (§4.6). Same line, different operation — the one place the "identical
control flow" claim needs a named abstraction rather than a shared expression.

One wrinkle to resolve in the build: `Tally._process_value_in` may run during deserialization
before `self.public_key` is populated. If so, fall back to dispatching on the dict's field set,
consistent with §2.4a.

### 3.3 The one sanctioned divergence: the decryption seam

ElGamal-Helios decrypts in two steps — each trustee publishes `α^x`, `decrypt_from_factors`
combines them, `DLogTable` recovers the exponent. Single-trustee Paillier yields `m` directly:
nothing to combine, no discrete log.

**Resolution.** Define the Paillier decryption factor to be the plaintext `m` itself, and make
`decrypt_from_factors` on the Paillier path a pass-through that never constructs a `DLogTable`.
Two reasons it is the right call rather than a fudge:

- It preserves the call graph exactly, and `Trustee.decryption_factors` — already typed
  `arrayOf(arrayOf('core/BigInteger'))` — stores it with no schema change.
- The absence of the dlog step becomes **visible and measurable** rather than hidden in a branch.
  That absence is the structural difference the study exists to characterise.

**Pre-argue it in the manuscript.** A panel reading "decryption works differently" without the
reasoning hears "the pipeline changed." §11 states it as the single sanctioned deviation with the
reason, and the instrumentation that follows from it: ElGamal decryption reported split into
`decryption_factor_time` / `dlog_precompute_time` / `dlog_lookup_time`, against Paillier's single
`decryption_time`.

### 3.4 Enforcement

Four gates, so "additive only" is testable rather than asserted:

1. The upstream ElGamal test suite passes unmodified on every commit.
2. **Golden-ballot test**: with fixed seed and key, an ElGamal `EncryptedAnswer` serializes
   byte-identically to a baseline captured before the first change. This catches drift in the
   §3.2 refactor, the change most likely to perturb ElGamal.
3. Diff gate: no line of `algs.py` or `elgamal.py` modified; `homomorphic.py` changes limited to
   the seven dispatch points.
4. The harness guard from §2.6 — a run cannot claim a scheme it did not execute.

---

## 4. Cryptographic specification

Everything needed to implement. Sources: Damgård–Jurik–Nielsen 2010 (§3, §3.2, §4.2, §5.1, §5.2,
§6) and Cramer–Damgård–Schoenmakers 1994 for the general L-way composition. Where a step is
derived here rather than quoted, it says so.

Throughout: `k = 1024` (prime size), so `|n| = 2048` and `|n²| = 4096`; `t = 160` (challenge
width, §4.9); `L(x) = (x−1)/n`.

### 4.1 Key generation

```
p, q   ←  distinct random primes, |p| = |q| = k = 1024
n      =  p·q
g      =  1 + n                        (DJN §3.2: may always be chosen so; pk reduces to n)
λ      =  lcm(p−1, q−1)
μ      =  λ⁻¹ mod n
```

The last line is a simplification worth taking. In general `μ = (L(g^λ mod n²))⁻¹ mod n`; with
`g = 1+n`, the binomial expansion gives `g^λ ≡ 1 + λn (mod n²)`, so `L(g^λ) = λ` and `μ` reduces
to a modular inverse with no exponentiation. Derived here; check it in the unit tests.

Public key: `(n)`, with `g = n+1` and `n² ` derived. Secret key: `(p, q, λ, μ)`.

**Why this forces a single trustee — and what Helios actually does, which is not DKG.**

Verified in the source. A multi-trustee ElGamal election works like this: the admin creates a
Trustee row with a name and email and no key (`views.new_trustee:399`); that person generates a
keypair **in their own browser**, keeps `xᵢ`, and uploads `yᵢ` with a Schnorr proof of knowledge
which the server verifies (`views.trustee_upload_pk:601`); at freeze the server multiplies the
uploaded keys, `combined_pk = Π pkᵢ` (`models.py:613-618`); at tally **every** trustee must publish
a decryption factor before `combine_decryptions` runs (`ready_for_decryption_combination:500`).

**There is no threshold machinery and no inter-trustee protocol.** The trustees never communicate.
There is no shared secret, no polynomial, no verifiable secret sharing — it is n-of-n, and losing
one trustee's key makes the election permanently undecryptable. Helios's own source states it
twice: `algs.py:530` and `elgamal.py:420` both carry `For now, no support for threshold` on the
decryption method, and a repository-wide search for Shamir, Lagrange, Feldman or Pedersen
secret-sharing returns nothing.

So Helios performs **independent local key generation plus multiplicative combination**, not
distributed key generation in the cryptographic sense. What makes it work is the hardcoded shared
`(p, q, g)`: every trustee generates a secret in the *same group*, so `y = Π yᵢ` corresponds to
`x = Σ xᵢ`.

**Paillier has no shared group to generate into.** Trustees would produce unrelated moduli `nᵢ`,
and there is no operation that combines RSA-style moduli into a joint public key. Paillier's
multi-party counterpart is the *threshold* variant, which does require genuine distributed key
generation — a protocol producing a shared `n` whose factorization nobody holds. That is out of
scope, so single-trustee is a consequence of the cryptosystem's structure, not a convenience.

Two consequences to carry into the manuscript, both in §11.2: phrase the scope limitation so it
does not imply a Helios feature was dropped, and state that **both arms are measured
single-trustee**, so the restriction is a difference in capability rather than a bias in the
numbers. Build spec §4.6 specifies the four places Helios must be made to refuse a second Paillier
trustee.

Validation, mirroring `EGPublicKey.validate_pk_params`: `n` odd and composite, `|n| ≥ 2048`,
`g == n+1`, `gcd(λ, n) == 1`, and for the secret key `p·q == n` with both prime.

### 4.2 Encryption, decryption, homomorphic addition

```
Enc(m, v)  =  (1+n)^m · v^n  mod n²   =   (1 + m·n) · v^n  mod n²,     v ←$ Z*_n
Dec(c)     =  L(c^λ mod n²) · μ       mod n
Add        =  Enc(m₁) · Enc(m₂) mod n²  =  Enc(m₁ + m₂ mod n)
```

The identity `(1+n)^m ≡ 1 + mn (mod n²)` is the mandated encryption optimization (§6): the
message component costs **one multiplication, not an exponentiation**. Only `v^n` costs. This is
one of the few places Paillier is structurally cheaper than ElGamal, which encodes the message as
`g^m`.

Two consequences used repeatedly below:

```
(1+n)^{−j}  ≡  1 − j·n   (mod n²)        for any j, since (1+jn)(1−jn) = 1 − j²n² ≡ 1
```

so every `u_j = c·(1+n)^{−m_j}` in §4.5–§4.7 is **one multiplication**, never an exponentiation.
And `Enc(0, v) = v^n mod n²`, i.e. an encryption of zero *is* an n-th power — which is exactly
the statement Π_root proves.

Sampling `v ←$ Z*_n`: draw uniformly in `[1, n)` and reject if `gcd(v, n) ≠ 1`. Rejection
probability is `1/p + 1/q ≈ 2^{−1023}`, so one draw always suffices in practice; keep the check
anyway, because a `v` sharing a factor with `n` would leak it.

### 4.3 CRT decryption (mandatory — §6)

**DJN does not specify this.** §4.2 of that paper gives one sentence — the standard trick "can
also be used here with the moduli p^j and q^j" — with no precomputation and no recombination
step. What follows is derived here from the mathematics, shaped after the Apache-2.0 Rust
implementation, and to be validated against `phe` as an external oracle (§7.2). Do not cite DJN
for the algorithm; cite it only for CRT being conventional practice.

Precompute, once per key:

```
L_p(x) = (x−1)/p          L_q(x) = (x−1)/q
h_p    = L_p(g^{p−1} mod p²)⁻¹ mod p
h_q    = L_q(g^{q−1} mod q²)⁻¹ mod q
p_inv  = p⁻¹ mod q
```

With `g = 1+n = 1+pq`, these have closed forms. `(1+pq)^{p−1} ≡ 1 + (p−1)pq (mod p²)` because
every higher binomial term carries `(pq)² ≡ 0 (mod p²)`; hence `L_p(g^{p−1}) = (p−1)q ≡ −q (mod p)`,
giving

```
h_p = (−q)⁻¹ mod p          h_q = (−p)⁻¹ mod q
```

Compute both ways in the tests and assert equality — it is a free check that the derivation and
the implementation agree.

Decrypt:

```
m_p  =  L_p(c^{p−1} mod p²) · h_p  mod p
m_q  =  L_q(c^{q−1} mod q²) · h_q  mod q
m    =  m_p + p · ((m_q − m_p) · p_inv  mod q)              (Garner)
```

Correct because `m ≡ m_p (mod p)` and `m ≡ m_q (mod q)`, and every tally satisfies `m < n`.

Cost: two exponentiations at a 2048-bit modulus with 1024-bit exponents, replacing one at 4096
bits with a 2048-bit exponent — a **~3.9× reduction** on that step (§5).

**CRT is available only to the party holding p and q.** The voter, the aggregating server and any
public verifier cannot use it. This is the structural fact that confines the whole
"unoptimized Paillier" objection to a single metric (§6).

### 4.4 Π_root — proof of knowledge of an n-th root

The Paillier analogue of Chaum–Pedersen, and the base of everything else. DJN §5.2 at `s = 1`.

```
Statement:   u ∈ Z*_{n²} is an n-th power:  ∃ v ∈ Z*_n such that u = v^n mod n²
Witness:     v

Commit:      r ←$ Z*_n              a = r^n mod n²
Challenge:   e ←$ [0, 2^t)
Response:    z = r · v^e mod n                      ← mod n, NOT mod n²
Verify:      z^n ≡ a · u^e  (mod n²)
             and gcd(z, n) = gcd(u, n) = gcd(a, n) = 1
```

**The reduction modulus in the response is not cosmetic.** Reducing `z` mod `n²` instead of `n`
leaves a proof that still verifies — because `z^n mod n²` depends only on `z mod n²` — while
making the honest branch's `z` about twice the bit-length of every simulated branch's. The real
branch then becomes identifiable by inspection, and ballot secrecy is gone. This is precisely the
bug in `ishaq/Paillier-E-Voting` (§7.2), it is invisible to functional testing, and §9.2 test 11
exists to catch it.

**Simulator**, for the false branches of §4.5:

```
Given e:     z ←$ Z*_n             a = z^n · u^{−e} mod n²
```

which satisfies the verification equation by construction and is distributed identically to an
honest transcript.

**Special soundness.** From two accepting transcripts `(a, e, z)` and `(a, e′, z′)` with `e ≠ e′`,
set `d = e − e′`. Since `0 < |d| < 2^t < min(p, q)`, `gcd(d, n) = 1`, so there exist `α, β` with
`αd + βn = 1`, and

```
v = (z/z′)^α · u^β mod n
```

extracts the witness, because `(z/z′)^n = u^d` gives `u = u^{αd+βn} = ((z/z′)^α u^β)^n`.

**The soundness bound is comfortable and worth stating in the manuscript.** Extraction requires
`2^t <` the smallest prime factor of `n`. At `t = 160` and 1024-bit primes there are ~864 bits of
margin, so Helios's existing SHA-1 challenge generator satisfies the bound without modification
(§4.9).

Cost: prover one exponentiation mod n² plus one small-exponent one mod n; verifier two mod n².
Compare Chaum–Pedersen: prover two, verifier four — **Π_root's commitment is one value where
Chaum–Pedersen's is two**, which is the reason Paillier's proof layer is relatively cheaper than
its ciphertext arithmetic alone would suggest (§5.2).

### 4.5 The 1-out-of-L disjunctive composition

CDS OR-composition over L instances of Π_root. DJN gives the 1-out-of-2 case explicitly; the
general L-way form is the standard CDS construction and should be cited to Cramer–Damgård–Schoenmakers
1994, not to DJN.

Given statements `u_0 … u_{L−1}`, of which exactly index `j*` is an n-th power with known witness
`v`:

```
1.  for each j ≠ j*:      e_j ←$ [0, 2^t)
                          z_j ←$ Z*_n
                          a_j = z_j^n · u_j^{−e_j} mod n²        (simulate, §4.4)

2.  for j = j*:           r ←$ Z*_n
                          a_{j*} = r^n mod n²

3.  s   = H(a_0, …, a_{L−1})                                     (§4.9)

4.  e_{j*} = (s − Σ_{j ≠ j*} e_j)  mod 2^t
    z_{j*} = r · v^{e_{j*}} mod n

5.  proof = [(a_0, e_0, z_0), …, (a_{L−1}, e_{L−1}, z_{L−1})]

Verify:   Σ_j e_j  ≡  H(a_0, …, a_{L−1})   (mod 2^t)
          z_j^n    ≡  a_j · u_j^{e_j}       (mod n²)      for every j
```

This mirrors `EGCiphertext.generate_disjunctive_encryption_proof` step for step, including the
callback shape: Helios computes the real challenge inside a `real_challenge_generator` closure
that first plants the real commitment, hashes all commitments, then subtracts the simulated
challenges. **Keep that structure**, so the call sites in `homomorphic.py` need no branching. The
only substantive difference is that Helios reduces the real challenge `% pk.q` and Paillier
reduces `% 2^t`.

Steps 1–2 must not be observably ordered — build the proof array by index, not by appending, so
the real branch's position is not inferable from anything but the (indistinguishable) values.

### 4.6 Ballot proofs

**Individual — "this ciphertext encrypts 0 or 1"**, one per answer slot, mirroring
`generate_disjunctive_encryption_proof(plaintexts=[g⁰,g¹], …)`:

```
u_0 = c                        (since (1+n)^{−0} = 1)
u_1 = c · (1 − n) mod n²       (since (1+n)^{−1} ≡ 1 − n)
real index = the encrypted bit,  witness v = the encryption randomness
L = 2
```

**Overall — "the number of selections is in [min, max]"**, one per question, mirroring the
`overall_proof` on `homomorphic_sum`:

```
C   = Π_i c_i mod n²                        homomorphic sum of the question's ciphertexts
V   = Π_i v_i mod n                         combined witness
u_j = C · (1 − (min+j)·n) mod n²            for j = 0 … L−1,   L = max − min + 1
real index = (number selected) − min
```

`V` is the correct witness because `(Π v_i)^n = Π v_i^n mod n²`. It is the multiplicative
analogue of Helios's `randomness_sum = (randomness_sum + r) % pk.q`, and the reason §3.2
introduces `combine_randomness` rather than sharing one expression.

For the 2025 NLE face: Q1 (Senator, min 0, max 12) → **L = 13**; Q2 (Party-list, min 0, max 1) →
**L = 2**. The 13-branch proof is the most expensive single object on the ballot after the 66
individual proofs.

**Declined, deliberately.** DJN §6.1's M-adic encoding compresses a vote to O(k log L) and needs
one decryption instead of L. It changes the ballot representation and would break the
structurally-identical-pipeline claim. Record it in limitations as a known optimization declined
for comparability — that is a strong thing to be able to say.

### 4.7 Proof of correct decryption

The Paillier counterpart of `EGSecretKey.decryption_factor_and_proof`. Single-trustee, publicly
verifiable, no threshold machinery. DJN §5.1 gives the threshold form; this is the single-trustee
specialisation, derived here.

```
Prover (trustee), given tally ciphertext c and recovered plaintext m:

  1.  u = c · (1 − m·n) mod n²                     now an n-th power
  2.  d = n⁻¹ mod λ                                exists because gcd(n, λ) = 1
  3.  v = u^d mod n                                the encryption randomness, recovered
  4.  run Π_root on (u, v), Fiat–Shamir            → (a, e, z)

Verifier (public), given c, claimed m, and (a, e, z):

      e  =  H(a)                       and       z^n ≡ a · (c · (1 − m·n))^e  (mod n²)
```

Step 3 is correct because `u ≡ v^n (mod n)` and `v^{nd} = v^{1+κλ} = v·(v^λ)^κ ≡ v (mod n)` by
Carmichael's theorem. Steps 3 and 4's commitment are both CRT-accelerable, since only the trustee
runs them.

**Hash the commitment only, not the statement.** That is weaker than best practice, but it is
exactly what Helios's ElGamal path does — `decryption_factor_and_proof` passes only
`proof.commitment` to `EG_fiatshamir_challenge_generator` — and matching it keeps the two arms
symmetric. Deviating would introduce an asymmetry in both cost and security posture. Note the
choice in limitations.

This is the concrete payoff of the single-trustee scope: a publicly verifiable proof of correct
decryption without distributed key generation. Record that reasoning in §6 of the manuscript.

### 4.8 Trustee proof of knowledge of the secret key

`generate_trustee` calls `secret_key.prove_sk(algs.DLog_challenge_generator)` — a Schnorr proof,
one exponentiation. Paillier's analogue is a proof of knowledge of the factorization
(Poupard–Stern): real work, no measurement payoff.

**Omit it, and document.** State in §6 that the Paillier variant generates no trustee
key-knowledge proof; quantify the ElGamal analogue from the harness's already-collected
`prove_sk_time_ns` (30 samples per run, present in every result file); show that omission cannot
materially advantage Paillier on any reported metric.

The `pok` field must still serialize to something or `Trustee` validation fails. Serialize an
explicit null marker, not an empty proof object — an empty proof would be a proof that verifies
vacuously.

### 4.9 The challenge generator, byte-exact

This is where cross-language builds fail silently. Specify it once, implement it twice, test it
first (§10, B1).

Helios's ElGamal generator concatenates the decimal strings of each commitment's `A` and `B` with
commas and SHA-1s the result. Python: `int(SHA1.new(bytes(s,'utf-8')).hexdigest(), 16)`.
JavaScript: `new BigInt(hex_sha1(strings.join(",")), 16)` where each string is
`commitment.A.toJSONObject()`, i.e. `BigInteger.toString()` at radix 10.

Paillier commitments are single values, so:

```
input   =  ",".join(decimal(a_0), decimal(a_1), …, decimal(a_{L−1}))
challenge = int(SHA1(utf8(input)).hexdigest(), 16)          ∈ [0, 2^160)
```

Rules that must hold identically in both languages:

- **Decimal**, radix 10, no leading zeros, no sign. All values are positive.
- **Separator** is one ASCII comma. No spaces, no trailing comma.
- **UTF-8** encoding of an ASCII-only string.
- **Canonicalise before stringifying**: `a` reduced mod n², `z` mod n, `e` mod 2^t. Two
  implementations that disagree only about whether a value was reduced will produce different
  hashes.
- SHA-1's output is exactly 160 bits, so `challenge < 2^t` always and the reduction mod 2^t is a
  no-op. State it anyway; do not omit it, because it documents the invariant.
- The single-commitment case (the §4.7 decryption proof) is the disjunctive generator called with
  a one-element list, exactly as `EG_fiatshamir_challenge_generator` wraps
  `EG_disjunctive_challenge_generator`.
- Simulated challenges are drawn uniformly from `[0, 2^160)` — in the booth, via
  `Random.getRandomInteger`, not a new RNG.

### 4.10 Serialization

Decimal strings throughout, matching `EGCiphertext.to_dict`'s `str(self.alpha)`. Switching to hex
or base64 would change measured ballot size and break comparability.

```jsonc
// ciphertext                                    legacy/EGCiphertext is {"alpha","beta"}
{"c": "<decimal, mod n²>"}

// proof — one Π_root transcript
{"commitment": "<decimal a>", "challenge": "<decimal e>", "response": "<decimal z>"}

// disjunctive proof — a BARE ARRAY, not an object
[ {…}, {…} ]

// public key
{"n": "<decimal>", "g": "<decimal, = n+1>"}

// secret key
{"public_key": {…}, "p": "…", "q": "…", "lambda": "…", "mu": "…"}
```

Three constraints that are easy to get wrong:

- **The disjunctive proof must serialize as a bare array.** `EGZKDisjunctiveProof` overrides
  `toDict` to return `…['proofs']` rather than the wrapping object. The Paillier datatype must do
  the same, or `individual_proofs` changes shape and the harness's `proof_bytes` slice breaks.
- **Keep the outer field names** `choices`, `individual_proofs`, `overall_proof`. The harness
  reads them by name and fails silently on a rename (§2.6).
- **Serialize `g` explicitly** even though it is `n+1`. It costs nothing, it mirrors
  `EGPublicKey`'s redundant four fields, and it gives `validate_pk_params` something to check.

The ciphertext keeps a different inner shape from ElGamal's `{alpha, beta}` necessarily. That
difference is a finding, not a problem — §5.3 predicts the two are at parity in bytes.

---

## 5. Cost model and predictions

Wall-clock times can always be argued about; modular-exponentiation counts at stated operand
widths cannot. This section gives the model, its predictions, and the one place where an existing
project document is wrong.

### 5.1 The unit error in `implementation_parity_defense.md` §4.2 — and what it changes

That document defines *"1 unit = one modexp with a 2048-bit modulus and a 2048-bit exponent"* and
scores ElGamal encryption as *"2 modexps @ 2048/2048."*

**ElGamal-Helios never uses a 2048-bit exponent.** Every exponent in the ElGamal path is drawn
from `Z_q`, and `q` is **256 bits** — `helios/views.py:46` is a 77-digit constant, and
`validate_pk_params` requires only `number.size(self.q) >= 256`. `random.mpz_lt(self.pk.q)`
supplies the randomness `r`, the commitment exponent `w`, and the response, all ≤ 256 bits.
Paillier's exponent, by contrast, is `n` itself — 2048 bits — and it is not a free parameter.

Modexp cost scales as `(modulus bits)² × (exponent bits)`, so a single Paillier exponentiation
costs `(4096/2048)² × (2048/256) = 4 × 8 = 32×` a single ElGamal one. The parity document's model
understates that by a factor of eight, and the error propagates into its headline claim that CRT
makes Paillier decryption *faster* than ElGamal.

Redefining the unit as **U = one modexp at a 2048-bit modulus with a 256-bit exponent**, and
recounting against the actual code:

| Operation, per answer slot | ElGamal | Paillier | Ratio |
|---|---|---|---|
| **Encryption + individual proof** | 7.25 U | 99.1 U | **13.7×** |
| **Decryption + proof, no CRT** | 3.00 U | 72.6 U | 24× |
| **Decryption + proof, with CRT** | 3.00 U | 18.6 U | **6.2×** |

CRT is worth **3.9×** on decryption — real, and mandatory for parity — but it does **not** flip
the winner. The corrected statement is: *Paillier decryption remains ~6× ElGamal per answer slot
even with CRT, because ElGamal's 256-bit exponent in a 2048-bit group is itself a large
structural advantage that CRT cannot close.*

This supersedes `implementation_parity_defense.md` §4.2 and its consequences for
`dlog_scope_boundary_resolution.md` §4. **Flagged as a derivation, not a measurement** — validate
it with the microbenchmark at milestone B2a (§10) before any of it enters the manuscript.

Counting detail, from the actual call graphs. ElGamal per slot (`elgamal.js`): `ElGamal.encrypt`
2 modPow; `Proof.generate` 2; `Proof.simulate` 4 (two at exponent 160, two at 256) — 8 modPow at
a 2048-bit modulus. Paillier per slot (§4.2, §4.5): `v^n` 1; real `a = r^n` 1; simulated
`a = z^n·u^{−e}` 2; response `v^e mod n` 1 — three at (4096, 2048), one at (4096, 160), one at
(2048, 160).

### 5.2 Why Paillier does better on proofs than on ciphertexts

A 13.7× encryption penalty is worse than the naive per-ciphertext ratio of ~2×, but it is *better*
than the 32×-per-operation figure, and the reason is structural: **Π_root's commitment is one
value where Chaum–Pedersen's is two.** ElGamal must compute `A = g^w` and `B = y^w`, and its
simulator must solve for both; Paillier computes a single `a = r^n` and its simulator solves for
one. Paillier does 4 exponentiations per slot where ElGamal does 8.

So the prediction has a shape, not just a number: Paillier loses on operand width and exponent
width, and claws back roughly half of it on operation count. Predicting this in the manuscript and
then confirming it against measurement reads far better than explaining it afterwards.

### 5.3 Ballot size — and the canary, corrected

Deriving from the serialization in §4.10, at 617 decimal digits per value mod n, 1234 mod n², 49
per 160-bit challenge, 78 per 256-bit ElGamal response, plus measured JSON punctuation:

| | ciphertext/slot | proof branch | ballot (222 slots + L=13 + L=2) | proof share |
|---|---|---|---|---|
| ElGamal | 1,256 B | 1,420 B | **909.5 KiB** | 70.1% |
| Paillier | 1,242 B | 1,946 B | **1,142.2 KiB** | 76.4% |

**The model reproduces the measured ElGamal ballot to within 1.2%** (909.5 KiB predicted against
920.9 KiB measured) and independently reproduces the ~70% proof share reported in
`claude/pivot_map.md` §3. That agreement is what licenses the Paillier figure.

Three results fall out:

- **Ciphertexts are at parity** — ratio 0.99. Two values mod p at 2048 bits against one mod n² at
  4096 bits is the same number of bits, and decimal encoding preserves it. Do not assert
  "Paillier ballots are bigger" as a ciphertext claim; the entire difference is proofs.
- **The ballot ratio is ~1.26×**, and Paillier's ballot is *more* proof-dominated (76% against
  70%).
- **The canary target is ~1.12 MiB, not the 1.19 MiB in `IMPLEMENTATION_SPEC.md` §2.6.** That
  figure assumed a 256-bit challenge; §4.9 fixes `t = 160`, which removes 29 digits from every
  proof branch. Using the old number would have raised a false alarm at milestone B8.

**Milestone B8 gate: measured Paillier ballot within 10% of 1,142 KiB.** Outside that, something
in the proof construction is wrong — most likely a branch count or a modulus mix-up.

### 5.4 What this means for feasibility

The measured ElGamal figure of 24.3 s/ballot over 222 slots and 8 modexp per slot implies
**~13.7 ms per 2048-bit jsbn modexp**. Encryption is essentially all cryptography — there is
little overhead room in that number — so the 13.7× ratio should carry through to wall clock,
predicting **~5.5 min/ballot** for Paillier in the booth.

That is consequential. Even N = 250 on the full face is ~23 hours of Paillier encryption alone.
The Paillier arm cannot be validated by a full sweep; validation has to come from the correctness
suite and small-N end-to-end runs, and the sweep design has to be revisited once B2a confirms or
refutes the ratio.

Decryption behaves oppositely. ElGamal's measured 20.72 ms per answer slot against a 3.00 U model
implies ~6.9 ms per unit, where a 2048-bit/256-bit modexp in CPython is nearer 0.5–1 ms — so
**roughly 85% of measured per-slot decryption time is scheme-independent framework overhead**
(object construction, serialization, Python attribute access). The measured decryption ratio will
therefore be compressed far below 6×. Saying so in advance, and instrumenting to separate
cryptographic from integration cost (`implementation_parity_defense.md` §6), is the difference
between a cost model and a claim.

Taking the model at face value: ElGamal decryption ≈ 4.6 s fixed + 23.8 µs × N; Paillier ≈ 28.6 s
flat. **Crossover at N ≈ 1.0 × 10⁶** — an order of magnitude above the study's 250,000 target,
and above anything reachable. The honest framing becomes: *Paillier's structural decryption
advantage exists but is not reached at deployable scale, because the dlog term ElGamal pays is
smaller than the operand-width penalty Paillier pays.* That is a scope result, and it is
reportable.

---

## 6. Parity: which optimizations are in, and where the ladder stops

`claude/implementation_parity_defense.md` settles the principle, and it stands: *each cryptosystem
is implemented with the optimizations that are standard and canonical for that cryptosystem in the
published voting-cryptography literature — not the maximum achievable by either, and not none.
Deviations in either direction are reported.*

| Scheme | Optimization | Status |
|---|---|---|
| Exp. ElGamal | Precomputed dlog table over the bounded tally | Helios's own, unmodified |
| Exp. ElGamal | 256-bit exponents in a 2048-bit group (`q`-order subgroup) | Helios's own, unmodified — and, per §5.1, a large advantage |
| Paillier | **CRT decryption via p² and q²** (§4.3) | **In** |
| Paillier | `(1+n)^m = 1+mn` (§4.2) | **In** |
| Paillier | DJN §4.1 alternative encryption function | **Out — see below** |
| Paillier | eCRT variants, FPGA acceleration | Out, and say so |

### 6.1 The one genuinely hard parity call: DJN §4.1

§5.1 shows ElGamal's advantage comes largely from a 256-bit exponent where Paillier uses a
2048-bit one. Paillier has a published counterpart: **DJN §4.1's alternative encryption function**,
which replaces `v^n` with `h^{vn}` for a fixed base `h` and a much shorter exponent, cutting
encryption cost substantially.

A panel member who reads §4.1 will ask why it was not used. The answer has to be better than "we
didn't."

**Recommendation: decline it, for a stated reason that is not cost.** Three grounds, in order of
strength:

1. **It changes the statement being proved.** Π_root proves knowledge of an n-th root. Under
   §4.1's encryption function the ciphertext is no longer of the form `(1+n)^m v^n` with `v`
   free, so the ballot-validity proof system must be redesigned — that is a research contribution
   in its own right, not an implementation detail, and it is outside a one-semester scope.
2. **It requires an additional security assumption** beyond decisional composite residuosity.
3. **It is an encryption-side optimization only**, so adopting it would improve one metric while
   leaving decryption, aggregation and verification untouched — changing the shape of the result
   rather than removing a handicap uniformly.

State the decline explicitly in limitations, with an estimate of its expected effect from the §5
model. Declining a known optimization *and quantifying what it would have bought* is a much
stronger position than not mentioning it.

### 6.2 The metric-by-metric exposure, restated with the corrected model

| Metric | Party doing the work | Holds p, q? | CRT available? | Exposed to the "unoptimized Paillier" objection? |
|---|---|---|---|---|
| Key generation | Trustee | — | n/a | Partly (prime-search strategy) |
| Encryption time | Voter (browser) | No | No | **No — structural** |
| Ballot size | — (representation) | — | n/a | **No — arithmetic on bit lengths** |
| Aggregation time | Server | No | No | **No — structural** |
| Decryption time | Trustee | **Yes** | **Yes** | **Yes — the one exposed metric** |
| Proof verification | Any public verifier | No | No | **No — structural** |

Five of six metrics are structurally immune, because the party performing the work does not hold
the factorization and so cannot apply the one optimization that changes operand width. That is
the single most useful sentence available in the defence: the objection has a real target, it is
exactly one metric, and it is named up front.

### 6.3 Ablations

Do not assert parity — measure what each canonical optimization is worth and report it as an
"optimization sensitivity" subsection:

1. **Paillier decryption with and without CRT.** Predicted 3.9× (§5.1). The largest single lever.
2. **ElGamal decryption with and without `DLogTable`** (substitute a naive search or BSGS).
   Quantifies what Helios's one optimization buys, and at which N it starts to matter.
3. **Paillier encryption with and without `(1+n)^m = 1+mn`.**

The claim then becomes *the finding survives across the optimization envelope of both schemes* —
or, if it does not, *the finding is conditional on optimization level X, which is stated*. Either
is defensible; an unqualified single-configuration result is not.

---

## 7. Resources

### 7.1 Primary sources — obtained and verified

- **Damgård, Jurik, Nielsen (2010),** IJIS 9(6):371–385. Full text confirmed fetchable at the
  MIT/Rivest mirror. Sections: **§3.2** the `g = n+1` simplification; **§4.1** the alternative
  encryption function (declined, §6.1); **§4.2** CRT, one sentence only; **§5.1** the decryption
  proof; **§5.2** the n^s-th power Σ-protocol and the 1-out-of-2 composition — **the core
  section**; **§6** the voting construction; **§6.1** M-adic ballots (declined, §4.6).
- **Damgård & Jurik,** BRICS RS-00-45 (2000) / PKC 2001 — free full version, useful for the
  literature review.
- **Cramer, Damgård, Schoenmakers (CRYPTO '94)** — **cite for the general 1-out-of-L
  composition.** DJN gives 1-out-of-2 only, and Q1 needs L = 13, so this citation is load-bearing.
- **ISO/IEC 18033-6:2019** — specifies *both* exponential ElGamal (§6.2) and Paillier (§6.3) in
  one normative document, with numerical examples in Annex B. Paywalled; the free preview stops
  before the annex. **Worth a UP library request**: one standard defining both arms materially
  strengthens the parity argument. No zero-knowledge proofs, so it validates the encryption layer
  only.

### 7.2 Code — what each can and cannot supply

| Resource | Licence | Verdict |
|---|---|---|
| **`data61/python-paillier` (`phe`)** | **GPLv3** | **External test oracle only.** Exact scheme match — `g=n+1`, CRT over p²/q². Dormant since 2022. No proofs. Its unit tests hard-code tiny keypairs (`p=43,q=59`; `p=293,q=433`) checkable by hand — excellent deterministic seeds. **Never copy its code into the fork:** GPLv3 into an Apache-2.0 codebase. |
| **`mhe/jspaillier`** | **MIT** | **Usable as-is — the JS starting point.** 98 lines on **jsbn**, already uses `(1+n)^m = 1+mn` in the exact optimised form. No CRT, no proofs. Swap its `SecureRandom` for Helios's `Random.getRandomInteger`. |
| `hardbyte/paillier.js` | Apache-2.0 | Usable, partial. jsbn-based, explicitly a JS port of `phe` by a `phe` maintainer — so it pairs with the Python oracle for a cross-language check. Incomplete by its own README. |
| `lovesh/generalized_paillier` (Rust) | Apache-2.0 | **Best algorithmic reference for the §4.3 CRT**, with `crt_combine` and proper p²/q² decryption. Licence does not contaminate. |
| `cryptovoting/damgard-jurik` | MIT | Reading only. Best-quality Python DJ code, but no proofs and no CRT (its `crm()` is a keygen step). Abandoned 2019. |
| `ishaq/Paillier-E-Voting` | **None — all rights reserved** | **Reading only, and instructive as a negative result.** The only Python code implementing a 1-out-of-L composition over the n-th root relation, and its verification equation matches DJN §5.2 — but it **leaks the vote** by reducing the real branch's response mod n² while simulated branches produce values < n, making the real branch identifiable by bit length. Verification still passes, so the bug is invisible to ordinary testing. Also samples randomness as a random *prime*, and is interactive rather than Fiat–Shamir. |
| `juanelas/paillier-bigint` | MIT | **Not usable** — native `BigInt`, disqualified by comparability. Same for `paillier-bignum` and the abandoned `paillier-js`. |
| `louismullie/hom-js` | GPLv3 | Not usable — same licence problem as `phe`. |
| UTD Paillier Toolbox (Java) | — | Reading only. The only implementation found anywhere with a **decryption** proof (`DecryptionZKP`); worth reading before writing §4.7. No OR-composition. |

**The `ishaq` bug earns a paragraph in the manuscript.** It is a concrete illustration of why the
reduction modulus in `z = r·v^e mod n` is not cosmetic, and it motivates test 11 in §9.2 —
comparing the bit-length distribution of real against simulated responses would have caught it
immediately.

### 7.3 jsbn — adequate, with one trap

Helios vendors its own jsbn (`jsbn.js` 560 lines, `jsbn2.js` 648). Every method §4 needs is
present: `modPow`, `modInverse`, `multiply`, `mod`, `gcd`, `isProbablePrime`. `bigint.js` aliases
it as `BigInt` and supplies the `toJSONObject`/`fromJSONObject` convention every serialized value
must implement.

**The trap:** Helios's copy is modified — Tom Wu's original indexes limbs as `this[i]`, Helios's
uses `this.arr[i]`. The public API is unchanged, so code written against the standard
`BigInteger` surface works untouched, but npm `jsbn` cannot be dropped in alongside it and no
internal-touching code can be lifted from elsewhere. **Depend only on public methods.**

Randomness is solved: `random.js`'s `Random.getRandomInteger(max)` draws from `sjcl.random` with
64 bits of headroom before reduction. Use it for `v ∈ Z*_n` and simulated challenges.

### 7.4 Prior art — the novelty claim holds, with one caveat

No Paillier variant of Helios exists, published or released. The only substantive crypto fork,
`RunasSudo/helios-server-mixnet`, keeps exponential ElGamal.

**The caveat is Ordinos** (Küsters et al., EuroS&P 2020), which *is* built on Helios and *does*
use threshold Paillier. Address it explicitly; three arguments separate it cleanly: its goal is
*tally-hiding* via MPC rather than a like-for-like performance comparison; its ballot-validity
proofs follow Schoenmakers–Veeningen, not DJN's n-th root Σ-protocol with CDS composition; and it
has no browser arm at all, being Python/gmpy2 server-side. Its code is *"available upon request"*
with no public URL, and the GitHub repositories search engines still index now return 404.

For related work: `pgrontas/Homomorphic-Voting-DJN` (C#/F#, unlicensed) is the one existing
implementation of the DJN voting protocol found anywhere. Cite and skim; not usable.

### 7.5 What must be written from scratch

1. **Π_root** (§4.4), Python and JavaScript. ~100 lines each side.
2. **The CDS 1-out-of-L composition** (§4.5), both languages.
3. **The decryption proof** (§4.7). Nothing in Python or JS has one.
4. **CRT decryption** (§4.3), Python only — the booth never decrypts.
5. **The Fiat–Shamir challenge convention** (§4.9). Every existing implementation is interactive
   or absent.
6. **Helios JSON serialization** for all of the above (§4.10).
7. **The correctness suite** (§9.2) — since no proof vectors exist anywhere, this suite *is* the
   correctness evidence.

The encryption layer is largely solved: `mhe/jspaillier` for the browser, `phe` as the server
oracle, `elgamal.js` as a proven structural template for the proof classes.

---

## 8. Decisions

Locked unless flagged. The build spec assumes these.

| # | Decision | Resolution |
|---|---|---|
| 1 | Scheme dispatch | §2.4 option (a) — object-declared datatype + dict-shape dispatch, plus a `crypto_scheme` column for queryability. **Confirm by spike (B0) before writing crypto.** |
| 2 | Where scheme behaviour lives | On the public key object; `homomorphic.py` ends with zero scheme references (§3.2) |
| 3 | CRT decryption | **In** (§4.3). Derived from the mathematics, shaped after the Apache-2.0 Rust reference, validated against `phe` |
| 4 | `(1+n)^m = 1+mn` | **In** (§4.2) |
| 5 | Optimization ladder stop | At CRT. DJN §4.1 declined with reasons (§6.1); eCRT and hardware out |
| 6 | Challenge hash | **SHA-1**, `t = 160`, matching ElGamal. Soundness argued from the 160-bit ≪ 1024-bit prime bound (§4.4). *Supersedes `IMPLEMENTATION_SPEC.md` §2.2.2* |
| 7 | Challenge summation modulus | `2^160`, identical in Python and JS (§4.9) |
| 8 | Response reduction modulus | **mod n**, never mod n² (§4.4) |
| 9 | Decryption-proof challenge input | Commitment only, mirroring Helios's ElGamal convention (§4.7) |
| 10 | Decryption seam | Paillier decryption factor := plaintext `m`; `decrypt_from_factors` is a pass-through (§3.3). Pre-argued in Methods as the one sanctioned deviation |
| 10a | Trustee count | **Exactly one**, enforced at four points (build spec §4.6). Forced by the DKG exclusion, not chosen — Paillier moduli are not combinable (§4.1) |
| 11 | Trustee `pok` | Omitted and documented, quantified against measured `prove_sk_time_ns` (§4.8) |
| 12 | M-adic compact ballots (DJN §6.1) | **Declined** for comparability; in limitations (§4.6) |
| 13 | JS bignum | Helios's vendored jsbn. Native `BigInt` would invalidate the comparison |
| 14 | Outer JSON field names | Identical to ElGamal; disjunctive proof serializes as a bare array (§4.10) |
| 15 | Key size | `\|p\| = \|q\| = 1024` → `\|n\| = 2048`, `\|n²\| = 4096`, matching ElGamal's 2048-bit `p` |
| 16 | Sixth metric: proof verification time | **In.** Already emitted as `proof_verification_time_ns` |
| 17 | Ballot size split into ciphertext + proof bytes | **In.** Already emitted |
| 18 | Ballot-size canary target | **1,142 KiB ± 10%** (§5.3). *Supersedes `IMPLEMENTATION_SPEC.md` §2.6's 1.19 MiB* |
| 19 | Skewed vote condition | **Dropped**, per `pivot_map.md` §6 — measures nothing under a precomputed table |
| 20 | N levels | **Deferred to the pilot gate**, and now also to B2a's confirmation of the §5 ratios |

Two open, neither blocking the build:

- **ISO/IEC 18033-6:2019** — request through the UP library? It would let Methods cite one
  normative definition covering both arms.
- **Ballot face as a second experimental factor** (`pivot_map.md` §7). Changes what the Paillier
  arm runs against; settle before the sweep, not before the build.

---

## 9. Risks and the correctness suite

### 9.1 Risks, by expected damage

1. **Cross-language proof disagreement.** A mismatch in hash input formatting means every ballot
   verifies locally and every cast fails, with the symptom far from the cause. §4.9 specifies it;
   milestone B1 tests it before either proof layer exists.
2. **Witness-indistinguishability bugs.** The `ishaq` class of failure passes every functional
   test. Mitigated by §4.4's `mod n` rule and test 11.
3. **Fast-but-unsound proofs.** Mitigated by tests 5–12.
4. **The harness attributing ElGamal results to Paillier** (§2.6). Closed by A1–A3.
5. **The bundle/worker split** (§2.5). Fails silently and differently depending on whether you
   test through the harness or the booth.
6. **Budget.** §5.4: at a predicted ~5.5 min/ballot, the Paillier arm cannot be validated by a
   full sweep. Validation comes from §9.2 and small-N end-to-end runs.

### 9.2 The correctness suite

Tests 1–4 are the manuscript's; 5–12 are additions. Each is stated so it can be written as an
executable specification without further design.

| # | Test | Setup | Passes when |
|---|---|---|---|
| 1 | Decryption correctness | Random keypair; m ∈ {0, 1, 2, …, 10⁶} and edge values 0, 1, n−1 | `Dec(Enc(m)) == m`, both the plain and CRT paths |
| 2 | Homomorphic addition | m₁, m₂ random with m₁+m₂ < n | `Dec(Enc(m₁)·Enc(m₂) mod n²) == m₁+m₂` |
| 3 | End-to-end tally | Known votes over the smoke face | Tally equals the plaintext sum, per slot |
| 4 | Schema conformance | Every new datatype | Round-trips through `LDObject` unchanged; decimal strings only |
| 5 | Individual-proof soundness | Ciphertext of 2, proved as 0/1 | Verification **fails** |
| 6 | Overall-proof soundness | 13 selections in a max-12 question | Verification **fails** |
| 7 | Completeness | 1,000 honest proofs, L ∈ {2, 13} | All verify |
| 8 | Decryption-proof soundness | Proof for a wrong `m` | Verification **fails** |
| 9 | **Cross-implementation agreement** | Every proof type, both directions | JS-generated verifies in Python and vice versa |
| 10 | **Special-soundness extraction** | Fixed commitment, two distinct challenges (§4.4) | Extracted `v` satisfies `v^n ≡ u (mod n²)` |
| 11 | **Response distribution** | ≥1,000 proofs; bit lengths of real vs simulated `z` | Distributions statistically indistinguishable — the `ishaq` canary |
| 12 | **Tamper matrix** | Perturb each of `a`, `e`, `z`, `u_j` independently; also permute the real index | Every perturbation **fails** verification |
| 13 | **CRT agreement** | Same ciphertexts through both decryption paths | Identical plaintexts; and `h_p` from the closed form equals `h_p` computed the long way (§4.3) |
| 14 | **Oracle agreement** | Fixed `(p, q, m, v)` against `phe` | Identical ciphertexts and plaintexts |
| 15 | **ElGamal golden ballot** | Fixed seed and key, pre-change baseline | Byte-identical serialization (§3.4) |

Tests 5, 6, 8, 10 and 12 are what make the word "verifiable" in the thesis title honest. Test 11
is what makes "secret" honest. Once validated, freeze a set of transcripts as regression fixtures
so later performance work cannot silently break correctness.

---

## 10. Sequencing

`pivot_map.md` §12 puts the harness audit first and Paillier sixth. They are mostly-independent
tracks, but three harness items sit on Objective 1's critical path because they decide whether a
Paillier election can be *measured* at all.

**Track A — harness:**

| | Item | Gates |
|---|---|---|
| A1 | Scheme guard in `runner.py` + acceptance cross-check (§2.6) | **the build** |
| A2 | Scheme-aware Stage 4 — no unconditional `DLogTable`, no dlog metrics under Paillier | **the build** |
| A3 | Acceptance: dlog metrics required for ElGamal only | **the build** |
| A4 | Timing-instrumentation audit (`pivot_map.md` §12 step 1) | the sweep |
| A5 | Re-run at N ∈ {10, 50, 100} to check linearity | the sweep |
| A6 | Decoupled dlog microbenchmark to 10⁶–10⁷ | the crossover figure |
| A7 | Persist the Stage 2 sub-walls currently discarded in `console.summary()` | profiling |

**Track B — Paillier build:**

| # | Milestone | Done when |
|---|---|---|
| B0 | **Datatype dispatch spike** (§2.4a) | `instantiate` precedence audited; a dummy non-ElGamal object round-trips through `LDObjectField` |
| B1 | **Challenge-vector agreement** (§4.9) | Fixed commitments produce identical challenge integers in Python and JS |
| B2 | `paillier.py`: keygen, enc, dec, CRT, homomorphic add (§4.1–4.3) | Tests 1–4, 13, 14 pass |
| B2a | **Modexp microbenchmark** | The §5.1 ratios confirmed or corrected on this machine, before anything from §5 enters the manuscript |
| B3 | `paillier.py`: Π_root, 1-out-of-L, decryption proof (§4.4–4.7) | Tests 5–8, 10–12 pass |
| B4 | `homomorphic.py` scheme-agnostic refactor (§3.2) | Test 15 passes; upstream suite green |
| B5 | `paillier.js` mirror | Test 9 passes both directions |
| B6 | Bundle + worker wiring (§2.5) | Both loaders carry `paillier.js`; harness and booth agree |
| B7 | Datatypes + models + views wired | Paillier election completes end-to-end in the browser |
| B8 | **Ballot-size canary** | Measured ballot within 10% of 1,142 KiB (§5.3) |
| B9 | Harness drives Paillier | `--scheme paillier` emits correct metrics and passes acceptance |
| B10 | Ablations (§6.3) | CRT on/off, `(1+n)^m` on/off, ElGamal dlog-table on/off, all measured |

B0 and B1 come before any cryptography, deliberately: they are the two cheapest ways to discover
the plan is wrong. B2a comes early for the same reason — if the 13.7× encryption prediction is
badly off, the sweep design changes before any of it is built.

---

## 11. Manuscript drafts

### 11.1 §9.2.3 — ballot validity proofs

*Replaces the paragraph beginning "The specific proof mechanisms to be used for verifying ballot
validity under Paillier-Helios … are currently under investigation."*

> **9.2.3 Ballot validity proofs under Paillier-Helios**
>
> ElGamal-Helios establishes ballot validity through disjunctive Chaum–Pedersen proofs composed
> by the technique of Cramer, Damgård and Schoenmakers (1994): each ciphertext carries a proof
> that it encrypts either 0 or 1, and the homomorphic product of a question's ciphertexts carries
> a proof that the number of selections lies within the question's declared range. The Paillier
> variant preserves this structure exactly, instantiating the same OR-composition over a
> different underlying Σ-protocol. This is a deliberate methodological choice: because the
> composition technique is held constant, the comparison isolates the cryptosystem rather than
> the proof strategy.
>
> The base protocol is the proof of knowledge of an n-th root given by Damgård, Jurik and Nielsen
> (2010, §5.2), which serves as the Paillier analogue of Chaum–Pedersen. To prove that a value
> *u* ∈ Z*_{n²} is an n-th power with witness *v*, the prover commits to *a* = *r*ⁿ mod n² for
> random *r* ∈ Z*_n, receives a *t*-bit challenge *e*, and responds with *z* = *r*·*v*^*e* mod
> *n*; the verifier accepts when *z*ⁿ ≡ *a*·*u*^*e* (mod n²). Special soundness holds provided
> 2^*t* is smaller than the smallest prime factor of *n*. The implementation reuses Helios's
> existing SHA-1 challenge generator, giving *t* = 160, which satisfies this bound with
> approximately 864 bits of margin at the 1024-bit prime size adopted here, and holds the hash
> function constant across both variants.
>
> Individual ballot proofs are obtained by applying this protocol to *u_j* = *c*·(1+n)^{−m_j} mod
> n² for each candidate plaintext *m_j* ∈ {0,1}; exactly one *u_j* is an n-th power, and the
> remaining branch is simulated in the standard way. The overall proof applies the same
> construction to the homomorphic product of the question's ciphertexts, with *L* = max − min + 1
> branches and the product of the individual randomness values as the combined witness — the
> multiplicative analogue of the additive randomness sum used in the ElGamal path. Damgård, Jurik
> and Nielsen present the two-branch case explicitly; the general *L*-branch composition follows
> Cramer, Damgård and Schoenmakers. All proofs are made non-interactive by the Fiat–Shamir
> transform, with branch challenges summing modulo 2^160.
>
> Correct decryption is proved without threshold machinery. Because gcd(*n*, λ) = 1, the trustee
> can recover the encryption randomness from the ciphertext and the decrypted plaintext, and then
> run the same n-th root protocol on that witness, yielding a publicly verifiable proof that the
> announced plaintext is correct. This is a direct consequence of the single-trustee scope
> adopted in §6, and is the principal methodological benefit of that scope decision.
>
> Three deviations are recorded. First, the Paillier variant generates no trustee proof of
> knowledge of the secret key; the ElGamal analogue is a single Schnorr proof whose measured cost
> is reported in Chapter 4, and its omission cannot materially affect any reported metric.
> Second, Damgård, Jurik and Nielsen (2010, §6.1) describe an M-adic ballot encoding that reduces
> ballot size and requires a single decryption rather than *L*; it is not implemented, because it
> would alter the ballot representation and so break the structural equivalence on which the
> comparison depends. Third, the alternative encryption function of the same work (§4.1), which
> would permit a shorter encryption exponent, is not implemented, because it changes the form of
> the ciphertext and therefore the statement that the ballot-validity proofs establish; redesigning
> the proof system around it is a separate contribution and lies outside the scope of this study.
> The expected effect of each omission is estimated in Chapter 4 rather than left unquantified.
>
> The Paillier implementation adopts the optimizations that are canonical for Paillier in the
> published literature — decryption via the Chinese Remainder Theorem over p² and q², and the
> (1+n)^m = 1+mn identity that removes one exponentiation from encryption — mirroring the
> treatment of ElGamal-Helios, which retains both Helios's precomputed discrete-logarithm table
> and its use of short exponents drawn from a 256-bit subgroup. Optimizations beyond this level,
> such as extended-CRT variants and hardware acceleration, are outside the scope of a software
> comparison and are implemented for neither scheme.
>
> One structural divergence from the ElGamal pipeline is unavoidable and is reported rather than
> concealed. ElGamal-Helios decrypts in two stages: each trustee publishes a decryption factor,
> the factors are combined, and the resulting group element is resolved to a tally through a
> precomputed discrete-logarithm table. Single-trustee Paillier decryption yields the plaintext
> directly, so there is no factor to combine and no discrete logarithm to resolve. The
> implementation therefore defines the Paillier decryption factor to be the plaintext itself and
> allows the combination step to pass it through unchanged, preserving Helios's call graph and its
> stored representation. This is not an incidental implementation detail: the absence of the
> discrete-logarithm stage is one of the structural differences the study sets out to
> characterise, and decryption cost is accordingly reported for ElGamal-Helios decomposed into
> decryption-factor computation, table precomputation and lookup, against a single decryption
> measurement for Paillier-Helios.

*Revision notes.* Cite CDS 1994 for the L-way composition, DJN §5.2 for Π_root, §5.1 for the
decryption proof, and §4.2 for CRT-as-standard-practice — but **not** DJN for a CRT algorithm,
which it does not give. If ISO/IEC 18033-6:2019 is obtained, cite §6.2 and §6.3 in the first
paragraph as normative definitions of both arms. The short-exponent sentence in the
second-to-last paragraph is doing real work: it pre-empts the §5.1 asymmetry rather than leaving
it to be discovered.

### 11.2 §6 and limitations — the trustee model

*Two passages. The first replaces any sentence of the form "distributed key generation is out of
scope," which is misleading (§4.1). The second belongs in the limitations section and is the
direct answer to a panel asking whether a one-trustee Paillier is a weaker system than the
ElGamal it is compared against.*

> **For §6, Scope and limitations.**
>
> Helios supports multiple trustees, but does so without any threshold or secret-sharing
> mechanism: each trustee independently generates a keypair in their own browser and publishes
> the public component with a proof of knowledge of the corresponding secret, and the election
> public key is formed as the product of these. Because all trustees generate their secrets in
> the same fixed group, the product of their public keys corresponds to the sum of their secret
> exponents, and decryption requires the participation of every trustee. The Helios source
> records the absence of threshold support explicitly.
>
> Paillier admits no counterpart to this construction. Trustees would generate unrelated moduli
> rather than secrets within a shared group, and there is no operation that combines such moduli
> into a joint public key. The multi-party counterpart for Paillier is its threshold variant,
> which requires a distributed key generation protocol producing a modulus whose factorisation no
> party holds. Such a protocol is outside the scope of this study, and the Paillier-Helios
> prototype therefore operates with a single trustee, namely the Helios server itself. This is a
> consequence of the cryptosystem's structure rather than a simplification adopted for
> convenience, and it is what permits the publicly verifiable proof of correct decryption
> described in §9.2.3.

> **For the limitations section.**
>
> The single-trustee restriction constitutes a difference in capability between the two
> prototypes: ElGamal-Helios can distribute trust across several trustees, whereas
> Paillier-Helios as implemented cannot. It does not, however, introduce a bias into the reported
> measurements. Every measured election in both arms is configured with a single trustee — the
> Helios server — because the workload generator drives Helios's standard election-creation path,
> which provisions exactly one server-held trustee. The two arms are therefore compared under
> identical trustee configurations, and the capability difference is reported here rather than
> reflected in any metric. Extending the comparison to a threshold setting would require
> implementing threshold Paillier and is identified as future work.

*Revision note.* If the manuscript already says "distributed key generation is out of scope,"
change it. As written it implies a Helios feature was excluded; Helios has no distributed key
generation, and a panel member who knows the system will notice.

---

## 12. What the build spec must add

The masterplan fixes *what* and *why*, and §4 fixes the mathematics. The build spec fixes *how*:

- Exact method signatures for `helios/crypto/paillier.py`, matched against the real
  `algs.py`/`elgamal.py` surfaces, plus the `helios/datatypes/paillier.py` `FIELDS` /
  `STRUCTURED_FIELDS` declarations
- The §3.2 public-key method contract with the ElGamal bodies written out, so the refactor is
  verifiably behaviour-preserving
- A worked example ballot in the §4.10 schema, small-key, for fixture use
- B0's acceptance criteria and its fallback path to §2.4 option (b)
- The §9.2 tests as executable specifications, with fixtures and tolerances
- Harness changes A1–A3, since they gate B9
- The bundle rebuild procedure from `build-helios-booth-compressed.txt`

---

## 13. Sources

**Papers.** Damgård, Jurik, Nielsen, *A Generalization of Paillier's Public-Key System with
Applications to Electronic Voting*, IJIS 9(6):371–385, 2010
([MIT mirror](https://people.csail.mit.edu/rivest/voting/papers/DamgardJurikNielsen-AGeneralizationOfPailliersPublicKeySystemWithApplicationsToElectronicVoting.pdf)) ·
Damgård & Jurik, BRICS [RS-00-45](https://www.brics.dk/RS/00/45/BRICS-RS-00-45.pdf) / PKC 2001 ·
Cramer, Damgård, Schoenmakers, CRYPTO 1994 ·
[ISO/IEC 18033-6:2019](https://www.iso.org/standard/67740.html) ·
Küsters et al., *Ordinos*, IEEE EuroS&P 2020 ([ePrint 2020/405](https://eprint.iacr.org/2020/405))

**Code.** [data61/python-paillier](https://github.com/data61/python-paillier) (GPLv3) ·
[mhe/jspaillier](https://github.com/mhe/jspaillier) (MIT) ·
[hardbyte/paillier.js](https://github.com/hardbyte/paillier.js/) (Apache-2.0) ·
[lovesh/generalized_paillier](https://github.com/lovesh/generalized_paillier) (Apache-2.0) ·
[cryptovoting/damgard-jurik](https://github.com/cryptovoting/damgard-jurik) (MIT) ·
[ishaq/Paillier-E-Voting](https://github.com/ishaq/Paillier-E-Voting) (unlicensed) ·
[pgrontas/Homomorphic-Voting-DJN](https://github.com/pgrontas/Homomorphic-Voting-DJN) ·
[RunasSudo/helios-server-mixnet](https://github.com/RunasSudo/helios-server-mixnet)

**Codebase, read directly at `d61eaa8`.** `helios/crypto/algs.py`, `helios/crypto/elgamal.py`,
`helios/workflows/homomorphic.py`, `helios/datatypes/__init__.py`, `helios/datatypes/legacy.py`,
`helios/datatypes/djangofield.py`, `helios/models.py`, `helios/views.py`,
`heliosbooth/js/jscrypto/elgamal.js`, `heliosbooth/js/jscrypto/helios.js`,
`heliosbooth/boothworker-single.js`, `heliosbooth/vote.html`; `workload/` runner, drivers,
`acceptance.py`, `emit.py`, `config/`, `results/`

**Companion documents.** `IMPLEMENTATION_SPEC.md` (Part 2 superseded by §4; Part 3 still current
for the harness) · `claude/implementation_parity_defense.md` (principle adopted in §6; **§4.2
superseded by §5.1**) · `claude/pivot_map.md` · `claude/run_analysis_n10.md` ·
`claude/dlog_scope_boundary_resolution.md` · `claude/decryption_not_bottleneck_evidence.md`