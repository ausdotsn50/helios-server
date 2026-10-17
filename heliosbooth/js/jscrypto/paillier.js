/*
 * Paillier cryptosystem for the Helios voting booth.
 *
 * Browser twin of helios/crypto/paillier.py. Structured as a mirror of
 * elgamal.js.
 */

var Paillier = {};

// Constants
Paillier.CHALLENGE_BITS = 160;
Paillier.CHALLENGE_MODULUS = BigInt.ONE.shiftLeft(160);
Paillier.DJN41_MODES = ['off', 'short', 'long'];
Paillier.TABLE_HEADROOM_BITS = 16;

Paillier.PublicKey = Class.extend({
  init: function(n, g, h, hn, djn41_mode) {
    this.n = n;
    this.g = g;          // == n+1, carried explicitly to mirror EGPublicKey
    this.n2 = n.multiply(n);
    this.djn41_mode = djn41_mode || 'off';
    this.h = h || null;      // -x^2 mod n
    this.hn = hn || null;    // h^n mod n^2
    this.tables = null;      // built on first use; see fixedBaseTables
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
  encrypt: function(plaintext, r) {
    if (r == null) { // safety mirror from eg
      r = this.randomRandomness();
    }
    var one_plus_mn = BigInt.ONE.add(plaintext.m.multiply(this.n)).mod(this.n2);

    // DJN 4.1: r is an EXPONENT against the fixed base hn, raised from the
    // fixed-base table -- one multiplication mod n^2 per set bit of r, and no
    // squarings.
    var blinding = this.usesDJN41()
        ? Paillier.fixedBasePow(this.hn, this.fixedBaseTables().hn, r, this.n2)
        : r.modPow(this.n, this.n2); // modPow: base, exp, mod

    return new Paillier.Ciphertext(one_plus_mn.multiply(blinding).mod(this.n2),
                                   this);
  },

  // DJN 4.1
  usesDJN41: function() {
    return this.djn41_mode != 'off';
  },

  // Exclusive upper bound on one DJN 4.1 exponent: 2^ceil(k/2) under 'short',
  // where k = |n|, and n // 2 under 'long'.
  exponentBound: function() {
    if (this.djn41_mode == 'short')
      return BigInt.ONE.shiftLeft(Math.ceil(this.n.bitLength() / 2)); // 1 shift left in k/2 places
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

  // The witness v with u = v^n mod n^2, derived from the stored randomness.
  // Standard: the randomness IS the witness. 
  proofWitness: function(randomness) {
    if (!this.usesDJN41())
      return randomness;

    // DJN 4.1: the randomness is an exponent a and the witness is h^a mod n, because
    // (h^a)^n = hn^a (mod n^2). 
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

  randomZStarN: function() {
    var v;
    do {
      v = Random.getRandomInteger(this.n);
    } while (v.equals(BigInt.ZERO) || !v.gcd(this.n).equals(BigInt.ONE));
    return v;
  },

  randomRandomness: function() {
    if (this.usesDJN41()) {
      // An exponent, not an element of Z*_n: uniform on [0, exponentBound()).
      return Random.getRandomInteger(this.exponentBound());
    }

    return this.randomZStarN();
  },

  // Standard: V = prod(v_i) mod n is the correct combined
  // witness because (prod v_i)^n = prod(v_i^n) mod n^2.
  combineRandomness: function(acc, r) {
    if (this.usesDJN41())
      return acc.add(r);

    return acc.multiply(r).mod(this.n);
  },

  randomnessIdentity: function() {
    return this.usesDJN41() ? BigInt.ZERO : BigInt.ONE;
  },

  disjunctiveChallengeGenerator: function() {
    return Paillier.disjunctive_challenge_generator; // PK object calls disjunctive challenge gen (src helios.js)
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

// Paillier Ciphertext obj
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

  // c encrypts j statement where if True only v^n remains
  statementFor: function(plaintext) {
    var mn = plaintext.m.multiply(this.pk.n);
    return this.c.multiply(BigInt.ONE.subtract(mn)).mod(this.pk.n2);
  },

  generateProof: function(plaintext, randomness, challenge_generator) {
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
    
    // Fake branch
    var proofs = _(list_of_plaintexts).map(function(plaintext, p_num) {
      if (p_num == real_index) {
        // no real proof yet
        return {};
      } else {
        // simulate
        return self.simulateProof(plaintext);
      }
    });

    // do the real proof
    var real_proof = this.generateProof(
        list_of_plaintexts[real_index], randomness, function(commitment) { // last arg is a func
      // set up the partial real proof so we're ready to get the hash
      proofs[real_index] = {'commitment': commitment};

      // get the commitments in a list and generate the whole disjunctive challenge
      var commitments = _(proofs).map(function(proof) {
        return proof.commitment;
      });

      var disjunctive_challenge = challenge_generator(commitments); // equiv to var s

      // now we must subtract all of the other challenges from this challenge
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


// Paillier plaintext obj
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


// DJN nth root proof

Paillier.Proof = Class.extend({
  // Proof constructor to designate a, e,z accodingly
  init: function(commitment, challenge, response) {
    this.commitment = commitment;
    this.challenge = challenge;
    this.response = response;
  },

  // Returns each proof in this json object format
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

Paillier.Proof.fromJSONObject = function(d) {
  return new Paillier.Proof(
      BigInt.fromJSONObject(d.commitment),
      BigInt.fromJSONObject(d.challenge),
      BigInt.fromJSONObject(d.response));
};

// Honest proof that u is an n-th power with witness v.
// For Paillier proof we need the values a,e,z
Paillier.Proof.generate = function(u, v, pk, challenge_generator) {
  var r = pk.randomZStarN(); 
  var a = r.modPow(pk.n, pk.n2); // Commit

  var e = challenge_generator(a); // Challenge
  var z = r.multiply(v.modPow(e, pk.n)).mod(pk.n); // Respond

  return new Paillier.Proof(a, e, z);
};

// Simulated transcript: given e, pick z and solve for a
/*
  For honest verifier simulation, the simulator chooses a 
  - random z ∈ Z∗n, 
  - a random e, 
  - sets a = E(0,z)u−e mod ns+1 and outputs (a,e,z)
*/
Paillier.Proof.simulate = function(u, pk, challenge) { // e as challenge
  if (challenge == null) {
    challenge = Random.getRandomInteger(Paillier.CHALLENGE_MODULUS);
  }

  var z = pk.randomZStarN();
  var a = z.modPow(pk.n, pk.n2)
           .multiply(u.modPow(challenge, pk.n2).modInverse(pk.n2))
           .mod(pk.n2);

  return new Paillier.Proof(a, challenge, z);
};


// Disjunctive proof
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

// null in, null out, as in ElGamal.DisjunctiveProof.fromJSONObject: a question
// with no max has no overall proof, and helios.js's verifyProofs requires it to
// come back as null.
Paillier.DisjunctiveProof.fromJSONObject = function(d) {
  if (d == null)
    return null;

  return new Paillier.DisjunctiveProof(
      _(d).map(function(p) {
        return Paillier.Proof.fromJSONObject(p);
      }));
};

// Module-level convenience mirroring ElGamal.encrypt(pk, plaintext, r).
Paillier.encrypt = function(pk, plaintext, r) {
  return pk.encrypt(plaintext, r);
};



// DJN 4.1 fixed-base exponentiation
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


// Challenge generator, used for real proof branch in Paillier
Paillier.disjunctive_challenge_generator = function(commitments) {
  var strings_to_hash = _(commitments).map(function(a) {
    return a.toJSONObject();
  });

  // SHA-1's output is exactly 160 bits
  // use Helios' own BigInt lib
  // hex_sha1(): takes a string and returns its SHA-1 digest written as a hex string
  return new BigInt(hex_sha1(strings_to_hash.join(",")), 16)
      .mod(Paillier.CHALLENGE_MODULUS);
};

Paillier.fiatshamir_challenge_generator = function(commitment) {
  return Paillier.disjunctive_challenge_generator([commitment]);
};
