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
 *
 * TWO STATISTICS, because bit length alone is blind under the 'long' mode.
 * Bit length catches a response drawn from a short range -- the bug above --
 * and ishaq's mod-n^2 reduction in the other direction. But a 'long' exponent
 * is drawn from [0, n/2), only one bit narrower than Z*_n, so a simulated
 * response drawn from THAT range would sit within noise of the real one by
 * bit length. It could never land in the top half of Z_n, though, where half
 * of all honest responses do. So each group's count above n/2 is reported
 * too.
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

  // Guards the guard: --reintroduce-bug puts the historic booth bug back --
  // proofs drawing from the encryption randomness instead of Z*_n -- so a
  // test can show this canary catches it.
  if (process.argv.includes('--reintroduce-bug')) {
    pk.randomZStarN = pk.randomRandomness;
  }

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
    djn41_mode: pk.djn41_mode,
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
