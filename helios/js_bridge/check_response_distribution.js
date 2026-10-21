/*
 * Test 11, JavaScript side — the response-distribution check for the booth.
 *
 *     node helios/js_bridge/check_response_distribution.js <pk.json> <trials>
 *
 * Real and simulated Pi_root responses must be indistinguishable, or the real
 * branch -- the vote -- can be read off the ballot. Test 11 checks the Python
 * prover; voters' proofs come from this one, so it is checked separately.
 *
 * Two statistics are reported. Bit length catches a response drawn from a
 * short range, and a mod-n^2 reduction in the other direction. A
 * response drawn from [0, n/2) is within noise of an honest one by bit length
 * but never lands above n/2, where half of all honest responses do, so each
 * group's count above n/2 is reported too.
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
      (j === realIndex ? real : simulated).push(p.response);
    });
  }

  const mean = (a) => a.reduce((x, y) => x + y, 0) / a.length;
  const bits = (zs) => zs.map((z) => z.bitLength());
  const half = pk.n.shiftRight(1);    // (n-1)/2, so z > half means z > n/2
  const aboveHalf = (zs) => zs.filter((z) => z.compareTo(half) > 0).length;

  console.log(JSON.stringify({
    trials: trials,
    all_verified: allVerified,
    real_mean_bits: mean(bits(real)),
    simulated_mean_bits: mean(bits(simulated)),
    delta_bits: Math.abs(mean(bits(real)) - mean(bits(simulated))),
    real_bits: bits(real),
    simulated_bits: bits(simulated),
    real_above_half: aboveHalf(real),
    simulated_above_half: aboveHalf(simulated),
  }, null, 2));
}

main();
