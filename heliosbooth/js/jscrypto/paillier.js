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
 * compareTo, shiftLeft, toString.
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

// Bit length of the DJN 4.1 short exponent. Must match DJN41_EXPONENT_BITS in
// helios/crypto/paillier.py -- a mismatch would not break correctness (both
// sides verify either way) but would silently make the browser and the server
// measure different things.
Paillier.DJN41_EXPONENT_BITS = 512;

Paillier.PublicKey = Class.extend({
  // h and g_prime are the DJN 4.1 parameters, absent on a standard key. Their
  // presence is what selects short-exponent mode; see usesDJN41 below.
  init: function(n, g, h, g_prime) {
    this.n = n;
    this.g = g;          // == n+1, carried explicitly to mirror EGPublicKey
    this.n2 = n.multiply(n);
    this.h = h || null;
    this.g_prime = g_prime || null;
  },

  usesDJN41: function() {
    return this.h != null;
  },

  toJSONObject: function() {
    var d = {n: this.n.toJSONObject(), g: this.g.toJSONObject()};
    if (this.usesDJN41()) {
      d.h = this.h.toJSONObject();
      d.g_prime = this.g_prime.toJSONObject();
    }
    return d;
  },

  // Enc(m, v) = (1 + m*n) * v^n mod n^2
  //
  // The message component is ONE MULTIPLICATION, never an exponentiation:
  // (1+n)^m = 1 + mn (mod n^2), because every binomial term from the third on
  // carries n^2. Only v^n costs. This is one of the few places Paillier is
  // structurally cheaper than ElGamal, which encodes its message as g^m.
  encrypt: function(plaintext, r) {
    if (r == null) {
      r = this.randomRandomness();
    }
    var one_plus_mn = BigInt.ONE.add(plaintext.m.multiply(this.n)).mod(this.n2);

    // DJN 4.1: r is an EXPONENT against the fixed base h, so this is a
    // (4096-bit modulus, ~512-bit exponent) modPow instead of (4096, 2048).
    var blinding = this.usesDJN41() ? this.h.modPow(r, this.n2)
                                    : r.modPow(this.n, this.n2);

    return new Paillier.Ciphertext(one_plus_mn.multiply(blinding).mod(this.n2),
                                   this);
  },

  // The Pi_root witness v with u = v^n mod n^2, derived from the stored
  // randomness. Standard: the randomness IS the witness. DJN 4.1: the
  // randomness is an exponent r and the witness is g'^(2r) mod n, which exists
  // because h is itself an n-th residue. This is the one step that keeps the
  // proof system unchanged between the two modes.
  proofWitness: function(randomness) {
    if (!this.usesDJN41())
      return randomness;

    return this.g_prime.modPow(BigInt.TWO.multiply(randomness), this.n);
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
  // uniform on Z*_n in BOTH modes. randomRandomness() is the ENCRYPTION
  // randomness, and under DJN 4.1 that is a short exponent -- wiring the proof
  // to it made simulated branches ~510 bits where the real branch was ~2045,
  // so the real branch was identifiable by bit length and ballot secrecy was
  // gone. Every proof still verified. This is the ishaq failure mode, and the
  // reason these two samplers are now distinct functions rather than one.
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
      // A short exponent, not an element of Z*_n.
      return Random.getRandomInteger(
          BigInt.ONE.shiftLeft(Paillier.DJN41_EXPONENT_BITS));
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
  // h^r1 * h^r2 = h^(r1+r2). No modulus -- reducing would need ord(h), which
  // divides lambda(n) and is secret. The sum stays small: 222 slots of
  // ~512-bit exponents is ~520 bits.
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

Paillier.PublicKey.fromJSONObject = function(d) {
  return new Paillier.PublicKey(
      BigInt.fromJSONObject(d.n),
      BigInt.fromJSONObject(d.g),
      d.h ? BigInt.fromJSONObject(d.h) : null,
      d.g_prime ? BigInt.fromJSONObject(d.g_prime) : null);
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

  // z^n == a * u^e (mod n^2), plus unit checks on z, u and a.
  verify: function(u, pk, challenge_generator) {
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
