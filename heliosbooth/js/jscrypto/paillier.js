/*
 * Paillier cryptosystem for the Helios voting booth.
 *
 * Browser twin of helios/crypto/paillier.py. Structured as a mirror of
 * elgamal.js, which is a proven template for this exact shape.
 *
 * BIGNUM: this file uses Helios's vendored jsbn via the BigInt wrapper in
 * bigint.js, and MUST NOT use native BigInt. Native BigInt would make Paillier
 * faster for reasons that have nothing to do with Paillier and would invalidate
 * the comparison the thesis exists to make. Helios's jsbn is also modified --
 * limbs are this.arr[i], not this[i] -- so only public methods are safe to
 * depend on: modPow, modInverse, multiply, mod, gcd, add, subtract, equals,
 * compareTo, signum, shiftLeft, shiftRight, bitLength, testBit, toString.
 */

var Paillier = {};

// ---------------------------------------------------------------------------
// Challenge generation (build spec §2.9)
// ---------------------------------------------------------------------------
//
// Byte-exact twin of paillier_disjunctive_challenge_generator in
// helios/crypto/paillier.py. Any disagreement here means every ballot verifies
// in the booth and every cast fails on the server, with the symptom nowhere
// near the cause -- so helios/fixtures/challenge_vectors.json pins both
// implementations to the same values, and milestone B1 tests it before any
// proof code exists on either side.

Paillier.CHALLENGE_BITS = 160;
Paillier.CHALLENGE_MODULUS = BigInt.ONE.shiftLeft(160);

Paillier.disjunctive_challenge_generator = function(commitments) {
  var strings_to_hash = _(commitments).map(function(a) {
    // toJSONObject rather than toString, matching elgamal.js's
    // "toJSONObject instead of toString because of IE weirdness". bigint.js
    // defines toJSONObject as this.toString(), i.e. radix 10 -- the same
    // decimal form Python's str(int) produces.
    return a.toJSONObject();
  });

  // SHA-1's output is exactly 160 bits, so the reduction is a no-op. It is kept
  // because it documents the invariant that a challenge is < 2^160, which the
  // branch-challenge summation in the disjunctive proof relies on.
  return new BigInt(hex_sha1(strings_to_hash.join(",")), 16)
      .mod(Paillier.CHALLENGE_MODULUS);
};

Paillier.fiatshamir_challenge_generator = function(commitment) {
  return Paillier.disjunctive_challenge_generator([commitment]);
};


// ---------------------------------------------------------------------------
// Public key
// ---------------------------------------------------------------------------

// The encryption function's mode, mirroring DJN41_MODES in
// helios/crypto/paillier.py: 'off' is standard Paillier, v^n; 'short' and
// 'long' are DJN 4.1's hn^a, with a from [0, 2^ceil(k/2)) or [0, n/2).
Paillier.DJN41_MODES = ['off', 'short', 'long'];

// How far past a single exponent the fixed-base tables reach. Mirrors
// TABLE_HEADROOM_BITS in helios/crypto/paillier.py: the overall proof's witness
// raises h to the SUM of a question's exponents.
Paillier.TABLE_HEADROOM_BITS = 16;

// [base^(2^i) mod modulus for i < bits], by repeated squaring.
Paillier.fixedBaseTable = function(base, modulus, bits) {
  var table = [base.mod(modulus)];
  for (var i = 1; i < bits; i++) {
    table.push(table[i - 1].multiply(table[i - 1]).mod(modulus));
  }
  return table;
};

// base^exponent mod modulus from table[i] = base^(2^i) mod modulus: one
// multiplication per set bit of the exponent, and no squarings -- those were
// paid once, when the table was built. Identical to modPow for every exponent;
// one the table cannot cover (negative, or too long) simply takes modPow.
Paillier.fixedBasePow = function(base, table, exponent, modulus) {
  var bits = exponent.bitLength();
  if (exponent.signum() < 0 || bits > table.length)
    return base.modPow(exponent, modulus);

  var result = BigInt.ONE;
  for (var i = 0; i < bits; i++) {
    if (exponent.testBit(i))
      result = result.multiply(table[i]).mod(modulus);
  }
  return result;
};

Paillier.PublicKey = Class.extend({
  // h, hn and djn41_mode are the DJN 4.1 parameters, absent on a standard key.
  // The mode travels with the key because a 'short' key and a 'long' key are
  // otherwise identical, and the booth sees nothing but the key.
  init: function(n, g, h, hn, djn41_mode) {
    this.n = n;
    this.g = g;          // == n+1, carried explicitly to mirror EGPublicKey
    this.n2 = n.multiply(n);
    this.djn41_mode = djn41_mode || 'off';
    this.h = h || null;      // -x^2 mod n
    this.hn = hn || null;    // h^n mod n^2
    this.tables = null;      // built on first use; see fixedBaseTables
  },

  usesDJN41: function() {
    return this.djn41_mode != 'off';
  },

  // Exclusive upper bound on one DJN 4.1 exponent: 2^ceil(k/2) under 'short',
  // where k = |n|, and n // 2 under 'long'.
  exponentBound: function() {
    if (this.djn41_mode == 'short')
      return BigInt.ONE.shiftLeft(Math.ceil(this.n.bitLength() / 2));
    if (this.djn41_mode == 'long')
      return this.n.shiftRight(1);
    return null;
  },

  // {hn: [hn^(2^i) mod n^2], h: [h^(2^i) mod n]}, built on the first
  // encryption under this key and cached on it, so every later encryption and
  // witness reuses them. DJN 4.2's cost claim assumes exactly this
  // precomputation. Sized like the Python side's: one exponent's bound plus
  // TABLE_HEADROOM_BITS, and anything longer falls back to modPow.
  fixedBaseTables: function() {
    if (this.tables == null) {
      var bits = this.exponentBound().bitLength() +
                 Paillier.TABLE_HEADROOM_BITS;
      this.tables = {
        hn: Paillier.fixedBaseTable(this.hn, this.n2, bits),
        h: Paillier.fixedBaseTable(this.h, this.n, bits)
      };
    }
    return this.tables;
  },

  toJSONObject: function() {
    var d = {n: this.n.toJSONObject(), g: this.g.toJSONObject()};
    if (this.usesDJN41()) {
      d.h = this.h.toJSONObject();
      d.hn = this.hn.toJSONObject();
      d.djn41_mode = this.djn41_mode;
    }
    return d;
  },

  // Enc(m, v) = (1 + m*n) * v^n mod n^2
  //
  // The message component is ONE MULTIPLICATION, never an exponentiation:
  // (1+n)^m = 1 + mn (mod n^2), because every binomial term from the third on
  // carries n^2. Only v^n costs. That is no saving over ElGamal, which never
  // exponentiates g^m per encryption either: generatePlaintexts builds g^0,
  // g^1, ... by a running product and ElGamal.encrypt multiplies the chosen one
  // in. The real gap is the blinding: here one modPow with a 4096-bit modulus
  // and a 2048-bit exponent; in ElGamal two with a 2048-bit modulus and a
  // 256-bit exponent (g^r and y^r, r from Z_q).
  encrypt: function(plaintext, r) {
    if (r == null) {
      r = this.randomRandomness();
    }
    var one_plus_mn = BigInt.ONE.add(plaintext.m.multiply(this.n)).mod(this.n2);

    // DJN 4.1: r is an EXPONENT against the fixed base hn, raised from the
    // fixed-base table -- one multiplication mod n^2 per set bit of r, and no
    // squarings.
    var blinding = this.usesDJN41()
        ? Paillier.fixedBasePow(this.hn, this.fixedBaseTables().hn, r, this.n2)
        : r.modPow(this.n, this.n2);

    return new Paillier.Ciphertext(one_plus_mn.multiply(blinding).mod(this.n2),
                                   this);
  },

  // The Pi_root witness v with u = v^n mod n^2, derived from the stored
  // randomness. Standard: the randomness IS the witness. DJN 4.1: the
  // randomness is an exponent a and the witness is h^a mod n, because
  // (h^a)^n = hn^a (mod n^2). This is the one step that keeps the proof system
  // unchanged between the modes.
  proofWitness: function(randomness) {
    if (!this.usesDJN41())
      return randomness;

    return Paillier.fixedBasePow(this.h, this.fixedBaseTables().h, randomness,
                                 this.n);
  },

  // --- the scheme-dispatch interface helios.js uses ------------------------
  // Mirrors the Python side in helios/crypto/paillier.py, so that
  // HELIOS.EncryptedAnswer.doEncryption needs no scheme branch beyond asking
  // the public key.

  // The integers themselves. ElGamal builds g^0, g^1, ... because
  // ElGamal.encrypt throws "Can't encrypt 0 with El Gamal"; Paillier encrypts
  // zero natively.
  generatePlaintexts: function(min, max) {
    if (min == null) min = 0;
    if (max == null) max = 1;

    var plaintexts = [];
    for (var i = min; i <= max; i++) {
      plaintexts.push(new Paillier.Plaintext(BigInt.fromInt(i), this));
    }
    return plaintexts;
  },

  // Uniform on Z*_n. SEPARATE from randomRandomness() on purpose.
  //
  // Pi_root's commitment randomness and its simulated responses must be
  // uniform on Z*_n in EVERY mode. randomRandomness() is the ENCRYPTION
  // randomness, and under DJN 4.1 that is an exponent from a narrower range --
  // wiring the proof to it made simulated branches ~510 bits where the real
  // branch was ~2045, so the real branch was identifiable by bit length and
  // ballot secrecy was gone. Every proof still verified. This is the ishaq
  // failure mode, and the reason these two samplers are distinct functions.
  randomZStarN: function() {
    var v;
    do {
      v = Random.getRandomInteger(this.n);
    } while (v.equals(BigInt.ZERO) || !v.gcd(this.n).equals(BigInt.ONE));
    return v;
  },

  randomRandomness: function() {
    // Random.getRandomInteger draws ceil(bitLength/32)+2 words from
    // sjcl.random and reduces -- 64 bits of headroom, so bias is negligible.
    // Do NOT introduce another RNG, and do not pull in jsbn's prng4/rng.
    if (this.usesDJN41()) {
      // An exponent, not an element of Z*_n: uniform on [0, exponentBound()).
      return Random.getRandomInteger(this.exponentBound());
    }

    var v;
    do {
      v = Random.getRandomInteger(this.n);
    } while (v.equals(BigInt.ZERO) || !v.gcd(this.n).equals(BigInt.ONE));
    return v;
  },

  // Standard: MULTIPLICATIVE. V = prod(v_i) mod n is the correct combined
  // witness because (prod v_i)^n = prod(v_i^n) mod n^2.
  //
  // DJN 4.1: ADDITIVE, because the randomness is an exponent and
  // hn^r1 * hn^r2 = hn^(r1+r2). No modulus -- reducing would need ord(h), which
  // divides lambda(n) and is secret. The sum outgrows one exponent only by
  // log2 of the number of summands, which TABLE_HEADROOM_BITS covers.
  combineRandomness: function(acc, r) {
    if (this.usesDJN41())
      return acc.add(r);

    return acc.multiply(r).mod(this.n);
  },

  randomnessIdentity: function() {
    return this.usesDJN41() ? BigInt.ZERO : BigInt.ONE;
  },

  disjunctiveChallengeGenerator: function() {
    return Paillier.disjunctive_challenge_generator;
  }
});

// Parses the DJN 4.1 fields as djn41_fields_from_dict does in
// helios/crypto/paillier.py -- including refusing the retired (h, g_prime)
// format rather than reading it as a standard key, which would quietly run a
// 'short' election as 'off'.
Paillier.PublicKey.fromJSONObject = function(d) {
  var mode = d.djn41_mode || 'off';
  if (!_(Paillier.DJN41_MODES).include(mode))
    throw "unknown djn41_mode: " + mode;

  if (mode == 'off') {
    if (d.h != null || d.hn != null || d.g_prime != null)
      throw "DJN 4.1 parameters without a djn41_mode: the retired " +
            "(h, g_prime) key format is no longer supported";
    return new Paillier.PublicKey(BigInt.fromJSONObject(d.n),
                                  BigInt.fromJSONObject(d.g));
  }

  if (d.h == null || d.hn == null)
    throw "a " + mode + " DJN 4.1 key must carry h and hn";

  return new Paillier.PublicKey(
      BigInt.fromJSONObject(d.n),
      BigInt.fromJSONObject(d.g),
      BigInt.fromJSONObject(d.h),
      BigInt.fromJSONObject(d.hn),
      mode);
};


// ---------------------------------------------------------------------------
// Plaintext
// ---------------------------------------------------------------------------

Paillier.Plaintext = Class.extend({
  // m is the integer ITSELF. There is no g^m encoding and no encode_m flag,
  // because Paillier needs neither.
  init: function(m, pk) {
    this.m = m;
    this.pk = pk;
  },

  getM: function() {
    return this.m;
  },

  toJSONObject: function() {
    return this.m.toJSONObject();
  }
});


// ---------------------------------------------------------------------------
// Ciphertext
// ---------------------------------------------------------------------------

Paillier.Ciphertext = Class.extend({
  init: function(c, pk) {
    this.c = c;
    this.pk = pk;
  },

  toJSONObject: function() {
    return {c: this.c.toJSONObject()};
  },

  // Homomorphic addition. The 0/1 identity cases mirror ElGamal.Ciphertext's
  // multiply, which is what lets helios.js keep initialising its running sum
  // to 0 without a scheme branch.
  multiply: function(other) {
    if (other == 0 || other == 1) {
      return this;
    }
    return new Paillier.Ciphertext(
        this.c.multiply(other.c).mod(this.pk.n2), this.pk);
  },

  // u_j = c * (1+n)^(-m_j) mod n^2 = c * (1 - m_j*n) mod n^2
  //
  // ONE MULTIPLICATION, never an exponentiation, since
  // (1 + j*n)(1 - j*n) = 1 - j^2 n^2 = 1 (mod n^2).
  //
  // Exactly one u_j is an n-th power -- the one matching the encrypted
  // message -- with the encryption randomness as witness. That is why Pi_root
  // is the right base protocol here.
  statementFor: function(plaintext) {
    var mn = plaintext.m.multiply(this.pk.n);
    return this.c.multiply(BigInt.ONE.subtract(mn)).mod(this.pk.n2);
  },

  generateProof: function(plaintext, randomness, challenge_generator) {
    // pk.proofWitness resolves the standard/DJN-4.1 difference; everything
    // downstream of this line is identical in both modes.
    return Paillier.Proof.generate(this.statementFor(plaintext),
                                   this.pk.proofWitness(randomness),
                                   this.pk, challenge_generator);
  },

  simulateProof: function(plaintext, challenge) {
    return Paillier.Proof.simulate(this.statementFor(plaintext), this.pk,
                                   challenge);
  },

  verifyProof: function(plaintext, proof, challenge_generator) {
    return proof.verify(this.statementFor(plaintext), this.pk,
                        challenge_generator);
  },

  // CDS 1-out-of-L composition. Mirrors ElGamal.Ciphertext.generateDisjunctiveProof
  // step for step, including the closure that plants the real commitment,
  // hashes all commitments and subtracts the simulated challenges. The only
  // substantive difference is that ElGamal reduces the real challenge mod q
  // and this reduces mod 2^160.
  generateDisjunctiveProof: function(list_of_plaintexts, real_index, randomness,
                                     challenge_generator) {
    var self = this;

    var proofs = _(list_of_plaintexts).map(function(plaintext, p_num) {
      if (p_num == real_index) {
        // no real proof yet
        return {};
      } else {
        // simulate!
        return self.simulateProof(plaintext);
      }
    });

    // do the real proof
    var real_proof = this.generateProof(
        list_of_plaintexts[real_index], randomness, function(commitment) {
      // set up the partial real proof so we're ready to get the hash
      proofs[real_index] = {'commitment': commitment};

      // get the commitments in a list and generate the whole disjunctive challenge
      var commitments = _(proofs).map(function(proof) {
        return proof.commitment;
      });

      var disjunctive_challenge = challenge_generator(commitments);

      // now we must subtract all of the other challenges from this challenge.
      var real_challenge = disjunctive_challenge;
      _(proofs).each(function(proof, proof_num) {
        if (proof_num != real_index)
          real_challenge = real_challenge.add(proof.challenge.negate());
      });

      // mod 2^160, the challenge modulus (ElGamal reduces mod q here)
      return real_challenge.mod(Paillier.CHALLENGE_MODULUS);
    });

    // set the real proof
    proofs[real_index] = real_proof;
    return new Paillier.DisjunctiveProof(proofs);
  },

  verifyDisjunctiveProof: function(list_of_plaintexts, disj_proof,
                                   challenge_generator) {
    var proofs = disj_proof.proofs;

    if (list_of_plaintexts.length != proofs.length)
      return false;

    // for loop because we want to bail out of the inner loop
    // if we fail one of the verifications.
    for (var i = 0; i < list_of_plaintexts.length; i++) {
      if (!this.verifyProof(list_of_plaintexts[i], proofs[i]))
        return false;
    }

    // check the overall challenge. Without this a prover could simulate every
    // branch, and ballot validity would mean nothing.
    var commitments = _(proofs).map(function(proof) {return proof.commitment;});
    var expected_challenge = challenge_generator(commitments);

    var sum = BigInt.ZERO;
    _(proofs).each(function(proof) {
      sum = sum.add(proof.challenge).mod(Paillier.CHALLENGE_MODULUS);
    });

    return expected_challenge.equals(sum);
  },

  equals: function(other) {
    return this.c.equals(other.c);
  }
});

Paillier.Ciphertext.fromJSONObject = function(d, pk) {
  return new Paillier.Ciphertext(BigInt.fromJSONObject(d.c), pk);
};


// ---------------------------------------------------------------------------
// Pi_root transcript
// ---------------------------------------------------------------------------

Paillier.Proof = Class.extend({
  // commitment is a SCALAR, where ElGamal.Proof's is {A, B}. Chaum-Pedersen
  // commits to two values; Pi_root commits to one. That is the reason
  // Paillier's proof layer is relatively cheaper than its ciphertext
  // arithmetic alone would suggest, and it is the discriminator the server's
  // datatype dispatch keys on.
  init: function(commitment, challenge, response) {
    this.commitment = commitment;
    this.challenge = challenge;
    this.response = response;
  },

  toJSONObject: function() {
    return {
      commitment: this.commitment.toJSONObject(),
      challenge: this.challenge.toJSONObject(),
      response: this.response.toJSONObject()
    };
  },

  // e in [0, 2^160), z^n == a * u^e (mod n^2), plus unit checks on z, u and a.
  verify: function(u, pk, challenge_generator) {
    // DJN 5.2: the challenge is "a random t bit number". verifyDisjunctiveProof
    // checks only that the branch challenges SUM to the hash mod 2^160, and a
    // false branch verifies for every challenge in one residue class mod n --
    // so without this bound, adding k*n to one challenge (n is odd, hence
    // invertible mod 2^160) forges a proof for any plaintext at all. Every
    // disjunctive branch passes through here.
    if (this.challenge.signum() < 0 ||
        this.challenge.compareTo(Paillier.CHALLENGE_MODULUS) >= 0)
      return false;

    var values = [this.response, u, this.commitment];
    for (var i = 0; i < values.length; i++) {
      if (!values[i].gcd(pk.n).equals(BigInt.ONE))
        return false;
    }

    var left = this.response.modPow(pk.n, pk.n2);
    var right = this.commitment.multiply(u.modPow(this.challenge, pk.n2))
                    .mod(pk.n2);

    if (!left.equals(right))
      return false;

    if (challenge_generator != null) {
      if (!this.challenge.equals(challenge_generator(this.commitment)))
        return false;
    }

    return true;
  }
});

// Honest proof that u is an n-th power with witness v.
//
// THE REDUCTION MODULUS IN THE RESPONSE IS NOT COSMETIC. z is reduced mod n,
// never mod n^2. Reducing mod n^2 still verifies -- z^n mod n^2 depends only on
// z mod n^2 -- while making the honest branch's z about twice the bit length of
// every simulated branch's, so the real branch becomes identifiable by
// inspection and ballot secrecy is gone. That is the bug in
// ishaq/Paillier-E-Voting, and it is invisible to functional testing.
Paillier.Proof.generate = function(u, v, pk, challenge_generator) {
  // randomZStarN, NOT randomRandomness: see the note on randomZStarN.
  var r = pk.randomZStarN();
  var a = r.modPow(pk.n, pk.n2);

  var e = challenge_generator(a);
  var z = r.multiply(v.modPow(e, pk.n)).mod(pk.n);   // mod n -- see above

  return new Paillier.Proof(a, e, z);
};

// Simulated transcript: given e, pick z and solve for a.
Paillier.Proof.simulate = function(u, pk, challenge) {
  if (challenge == null) {
    challenge = Random.getRandomInteger(Paillier.CHALLENGE_MODULUS);
  }

  // randomZStarN, NOT randomRandomness: a simulated response drawn from the
  // encryption randomness would be short under DJN 4.1 and would give the real
  // branch away.
  var z = pk.randomZStarN();
  var a = z.modPow(pk.n, pk.n2)
           .multiply(u.modPow(challenge, pk.n2).modInverse(pk.n2))
           .mod(pk.n2);

  return new Paillier.Proof(a, challenge, z);
};

Paillier.Proof.fromJSONObject = function(d) {
  return new Paillier.Proof(
      BigInt.fromJSONObject(d.commitment),
      BigInt.fromJSONObject(d.challenge),
      BigInt.fromJSONObject(d.response));
};


// ---------------------------------------------------------------------------
// Disjunctive proof — serializes as a BARE ARRAY
// ---------------------------------------------------------------------------

Paillier.DisjunctiveProof = Class.extend({
  init: function(list_of_proofs) {
    this.proofs = list_of_proofs;
  },

  toJSONObject: function() {
    return _(this.proofs).map(function(proof) {
      return proof.toJSONObject();
    });
  }
});

Paillier.DisjunctiveProof.fromJSONObject = function(d) {
  return new Paillier.DisjunctiveProof(
      _(d).map(function(p) {
        return Paillier.Proof.fromJSONObject(p);
      }));
};

// Module-level convenience mirroring ElGamal.encrypt(pk, plaintext, r).
Paillier.encrypt = function(pk, plaintext, r) {
  return pk.encrypt(plaintext, r);
};
