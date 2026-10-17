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

Paillier.PublicKey = Class.extend({
  init: function(n, g) {
    this.n = n;
    this.g = g;          // == n+1, carried explicitly to mirror EGPublicKey
    this.n2 = n.multiply(n);
  },

  toJSONObject: function() {
    var d = {n: this.n.toJSONObject(), g: this.g.toJSONObject()};
    return d;
  },

  // Enc(m, v) = (1 + m*n) * v^n mod n^2
  encrypt: function(plaintext, r) {
    if (r == null) { // safety mirror from eg
      r = this.randomRandomness();
    }
    var one_plus_mn = BigInt.ONE.add(plaintext.m.multiply(this.n)).mod(this.n2);

    var blinding = r.modPow(this.n, this.n2); // modPow: base, exp, mod

    return new Paillier.Ciphertext(one_plus_mn.multiply(blinding).mod(this.n2),
                                   this);
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
    return this.randomZStarN();
  },

  // Standard: V = prod(v_i) mod n is the correct combined
  // witness because (prod v_i)^n = prod(v_i^n) mod n^2.
  combineRandomness: function(acc, r) {
    return acc.multiply(r).mod(this.n);
  },

  randomnessIdentity: function() {
    return BigInt.ONE;
  },

  disjunctiveChallengeGenerator: function() {
    return Paillier.disjunctive_challenge_generator; // PK object calls disjunctive challenge gen (src helios.js)
  }
});

Paillier.PublicKey.fromJSONObject = function(d) {
  return new Paillier.PublicKey(BigInt.fromJSONObject(d.n),
                                BigInt.fromJSONObject(d.g));
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
                                   randomness,
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
