/*
 * Test 11, JavaScript side — the ishaq canary for the booth.
 *
 *     node helios/js_bridge/check_response_distribution.js <pk.json> <trials>
 *
 * WHY THIS EXISTS SEPARATELY FROM THE PYTHON TEST
 * ------------------------------------------------
 * Test 11 in helios/tests_paillier.py checks that real and simulated Pi_root
 * responses are indistinguishable by bit length. It only ever ran against the
 * Python implementation -- and the Python implementation was correct.
 *
 * The JavaScript one was not. When DJN 4.1 landed, Paillier.Proof.generate and
 * .simulate were drawing their randomness from pk.randomRandomness(), which
 * 4.1 redefines from "uniform on Z*_n" to "a short exponent". Simulated
 * branches came out at ~510 bits against the real branch's ~2045, so the
 * voter's actual selection was readable straight off the ballot.
 *
 * Every proof still verified. Cross-language agreement still passed. The
 * ballot-size canary moved by 12%, which is the only reason it was noticed.
 *
 * A secrecy property that is only checked on one side of a two-language
 * implementation is not checked. This closes that gap.
 */

const fs = require('fs');
const {createBoothContext} = require('./booth_context');

function main() {
  const pk_json = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  const trials = parseInt(process.argv[3] || '40', 10);

  const ctx = createBoothContext();
  const B = ctx.BigInt;
  const P = ctx.Paillier;

  const pk = P.PublicKey.fromJSONObject(pk_json);
  const plaintexts = pk.generatePlaintexts(0, 1);

  const real = [];
  const simulated = [];
  let allVerified = true;

  for (let i = 0; i < trials; i++) {
    const realIndex = i % 2;
    const r = pk.randomRandomness();
    const c = pk.encrypt(new P.Plaintext(B.fromInt(realIndex), pk), r);
    const proof = c.generateDisjunctiveProof(
        plaintexts, realIndex, r, P.disjunctive_challenge_generator);

    if (!c.verifyDisjunctiveProof(plaintexts, proof,
                                  P.disjunctive_challenge_generator)) {
      allVerified = false;
    }

    proof.proofs.forEach(function(p, j) {
      (j === realIndex ? real : simulated).push(p.response.bitLength());
    });
  }

  const mean = (a) => a.reduce((x, y) => x + y, 0) / a.length;

  console.log(JSON.stringify({
    uses_djn_41: pk.usesDJN41(),
    trials: trials,
    all_verified: allVerified,
    real_mean_bits: mean(real),
    simulated_mean_bits: mean(simulated),
    delta_bits: Math.abs(mean(real) - mean(simulated)),
    real_bits: real,
    simulated_bits: simulated,
  }, null, 2));
}

main();
