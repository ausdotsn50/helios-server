/*
 * Test 9 — cross-implementation proof agreement.
 *
 *     node helios/js_bridge/crosscheck_proofs.js <input.json> > <output.json>
 *
 * Helios's real pipeline generates proofs in the browser and verifies them on
 * the server. If the two implementations disagree on anything -- challenge-hash
 * input formatting, byte order, separators, leading zeros, which modulus a value
 * was reduced by -- then every ballot verifies locally in the booth and every
 * cast fails at the server, with the symptom nowhere near the cause.
 *
 * This is the test that catches that class of bug. It runs both directions:
 *
 *   Python -> JS   the `cases` in the input were built by helios/crypto/paillier.py;
 *                  this script verifies them with the booth's own code.
 *   JS -> Python   this script generates fresh proofs and emits them;
 *                  helios/tests_paillier.py verifies those in Python.
 *
 * One direction alone is not enough: two implementations that share a formatting
 * mistake would agree with each other and disagree with the specification.
 * Running both against fixed vectors from helios/fixtures/challenge_vectors.json
 * is what pins them to the spec rather than to each other.
 */

const fs = require('fs');
const {createBoothContext} = require('./booth_context');

function main() {
  const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  const ctx = createBoothContext();
  const B = ctx.BigInt;
  const P = ctx.Paillier;

  const pk = P.PublicKey.fromJSONObject(input.public_key);

  const verified = [];
  const generated = [];

  // ---- direction 1: verify Python-generated proofs -----------------------
  for (const c of input.cases) {
    const ct = P.Ciphertext.fromJSONObject(c.ciphertext, pk);
    const plaintexts = pk.generatePlaintexts(c.min, c.max);
    const proof = P.DisjunctiveProof.fromJSONObject(c.proof);

    let ok;
    try {
      ok = ct.verifyDisjunctiveProof(plaintexts, proof,
                                     P.disjunctive_challenge_generator);
    } catch (e) {
      ok = `<threw ${e.message}>`;
    }
    verified.push({label: c.label, expected: c.should_verify, got: ok,
                   ok: ok === c.should_verify});
  }

  // ---- decryption proofs, Python -> JS ------------------------------------
  // The booth never decrypts, so this direction only ever runs one way. The
  // statement is the same c*(1 - m*n) the ballot proofs use, so verifyProof
  // serves directly.
  for (const d of (input.decryption_cases || [])) {
    const ct = P.Ciphertext.fromJSONObject(d.ciphertext, pk);
    const claimed = new P.Plaintext(B.fromJSONObject(d.plaintext), pk);
    const proof = P.Proof.fromJSONObject(d.proof);

    let ok;
    try {
      ok = ct.verifyProof(claimed, proof, P.fiatshamir_challenge_generator);
    } catch (e) {
      ok = `<threw ${e.message}>`;
    }
    verified.push({label: d.label, expected: d.should_verify, got: ok,
                   ok: ok === d.should_verify});
  }

  // ---- direction 2: generate proofs for Python to verify ------------------
  for (const spec of input.generate) {
    const plaintexts = pk.generatePlaintexts(spec.min, spec.max);

    if (spec.kind === 'individual') {
      const r = pk.randomRandomness();
      const ct = pk.encrypt(
          new P.Plaintext(B.fromInt(spec.real_index + spec.min), pk), r);
      const proof = ct.generateDisjunctiveProof(
          plaintexts, spec.real_index, r, P.disjunctive_challenge_generator);

      generated.push({
        label: spec.label, kind: spec.kind,
        min: spec.min, max: spec.max, real_index: spec.real_index,
        ciphertext: ct.toJSONObject(),
        // so Python can re-encrypt under the same randomness: a proof verifies
        // whatever encryption function made the ciphertext, so agreement on
        // proofs alone would not show the booth used the key's DJN 4.1 mode
        randomness: r.toJSONObject(),
        proof: proof.toJSONObject(),
        self_verifies: ct.verifyDisjunctiveProof(
            plaintexts, proof, P.disjunctive_challenge_generator),
      });
    } else if (spec.kind === 'overall') {
      // Homomorphic sum of `spec.n_slots` ciphertexts, `spec.selected` of them
      // encrypting 1 -- the shape a real overall proof has.
      let C = 0;
      let V = pk.randomnessIdentity();
      for (let i = 0; i < spec.n_slots; i++) {
        const bit = i < spec.selected ? 1 : 0;
        const r = pk.randomRandomness();
        const c = pk.encrypt(new P.Plaintext(B.fromInt(bit), pk), r);
        C = c.multiply(C);
        V = pk.combineRandomness(V, r);
      }
      const proof = C.generateDisjunctiveProof(
          plaintexts, spec.selected - spec.min, V,
          P.disjunctive_challenge_generator);

      generated.push({
        label: spec.label, kind: spec.kind,
        min: spec.min, max: spec.max, selected: spec.selected,
        ciphertext: C.toJSONObject(),
        randomness: V.toJSONObject(),    // the combined randomness
        proof: proof.toJSONObject(),
        self_verifies: C.verifyDisjunctiveProof(
            plaintexts, proof, P.disjunctive_challenge_generator),
      });
    }
  }

  console.log(JSON.stringify({
    ok: verified.every((v) => v.ok) && generated.every((g) => g.self_verifies),
    djn41_mode: pk.djn41_mode,    // the mode the booth parsed from the key
    verified: verified,
    generated: generated,
  }, null, 2));
}

main();
