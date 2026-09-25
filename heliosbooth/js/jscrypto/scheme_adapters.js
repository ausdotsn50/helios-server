/*
 * Scheme-dispatch adapters for the booth.
 *
 * Browser twin of helios/crypto/scheme_adapters.py, and it exists for the same
 * reason. helios.js needs to build ballots without naming a cryptosystem, so
 * the scheme-specific behaviour moves onto the public key object, which
 * helios.js already holds everywhere it matters.
 *
 * The Paillier side lives on Paillier.PublicKey in paillier.js. The ElGamal
 * side is attached here rather than edited into elgamal.js, so that file stays
 * byte-identical -- the control arm of the experiment must not move.
 *
 * Every body below is COPIED VERBATIM from the helios.js call site it replaces,
 * so the refactor is behaviour-preserving by construction. Line references are
 * to the pre-refactor helios.js.
 *
 * Load order: after elgamal.js and paillier.js, before helios.js.
 */

var CRYPTO = {};

// --- ElGamal side ----------------------------------------------------------

// Was UTILS.generate_plaintexts (helios.js:192-209).
//
// Builds g^0, g^1, ... because ElGamal.encrypt throws "Can't encrypt 0 with El
// Gamal". Paillier encrypts zero natively and returns the integers themselves,
// which is exactly why this cannot stay a shared expression.
ElGamal.PublicKey.prototype.generatePlaintexts = function(min, max) {
  var last_plaintext = BigInt.ONE;

  // an array of plaintexts
  var plaintexts = [];

  if (min == null)
    min = 0;

  // questions with more than one possible answer, add to the array.
  for (var i = 0; i <= max; i++) {
    if (i >= min)
      plaintexts.push(new ElGamal.Plaintext(last_plaintext, this, false));
    last_plaintext = last_plaintext.multiply(this.g).mod(this.p);
  }

  return plaintexts;
};

// Was Random.getRandomInteger(pk.q) (helios.js:273).
//
// Note the exponent is drawn from Z_q with q of 256 bits, not from Z_p. That
// short exponent in a 2048-bit group is ElGamal's single largest structural
// advantage in the cost model.
ElGamal.PublicKey.prototype.randomRandomness = function() {
  return Random.getRandomInteger(this.q);
};

// Was rand_sum.add(randomness[i]).mod(pk.q) (helios.js:294).
// ElGamal sums; Paillier multiplies mod n.
ElGamal.PublicKey.prototype.combineRandomness = function(acc, r) {
  return acc.add(r).mod(this.q);
};

// ElGamal accumulates additively, so the identity is 0. helios.js seeds its
// running sum from randomness[0] rather than the identity, so this is only
// used where an explicit starting value is needed.
ElGamal.PublicKey.prototype.randomnessIdentity = function() {
  return BigInt.ZERO;
};

ElGamal.PublicKey.prototype.disjunctiveChallengeGenerator = function() {
  return ElGamal.disjunctive_challenge_generator;
};

ElGamal.PublicKey.prototype.encrypt = function(plaintext, r) {
  return ElGamal.encrypt(this, plaintext, r);
};

ElGamal.PublicKey.prototype.ciphertextFromJSONObject = function(d) {
  return ElGamal.Ciphertext.fromJSONObject(d, this);
};

// --- Paillier side ---------------------------------------------------------
// (Paillier.PublicKey already carries generatePlaintexts, randomRandomness,
//  combineRandomness, randomnessIdentity, disjunctiveChallengeGenerator and
//  encrypt; only the ciphertext deserializer is added here for symmetry.)

if (typeof Paillier !== 'undefined' && Paillier.PublicKey) {
  Paillier.PublicKey.prototype.ciphertextFromJSONObject = function(d) {
    return Paillier.Ciphertext.fromJSONObject(d, this);
  };
}

// --- scheme identification -------------------------------------------------

/*
 * Deserialize an election public key without being told which scheme it is.
 *
 * Dispatches on the serialized field set, matching helios/datatypes/__init__.py
 * on the server: an ElGamal public key carries y, p, g, q; a Paillier public
 * key carries n and g. The discriminators are disjoint by construction rather
 * than by convention, so a key cannot be misread as the wrong scheme.
 */
CRYPTO.publicKeyFromJSONObject = function(d) {
  if (d == null)
    return null;

  if (d.y != null)
    return ElGamal.PublicKey.fromJSONObject(d);

  if (d.n != null && typeof Paillier !== 'undefined')
    return Paillier.PublicKey.fromJSONObject(d);

  // Unrecognised: keep the historical behaviour and its error message rather
  // than inventing a new one.
  return ElGamal.PublicKey.fromJSONObject(d);
};

// --- proof deserializers ---------------------------------------------------
// helios.js rebuilds stored proofs when loading a cast ballot or a trustee
// record, and the two schemes' transcripts differ in shape: a Chaum-Pedersen
// commitment is {A, B}, a Pi_root commitment is a scalar.

ElGamal.PublicKey.prototype.disjunctiveProofFromJSONObject = function(d) {
  return ElGamal.DisjunctiveProof.fromJSONObject(d);
};

ElGamal.PublicKey.prototype.proofFromJSONObject = function(d) {
  return ElGamal.Proof.fromJSONObject(d);
};

if (typeof Paillier !== 'undefined' && Paillier.PublicKey) {
  Paillier.PublicKey.prototype.disjunctiveProofFromJSONObject = function(d) {
    return Paillier.DisjunctiveProof.fromJSONObject(d);
  };

  Paillier.PublicKey.prototype.proofFromJSONObject = function(d) {
    return Paillier.Proof.fromJSONObject(d);
  };
}
