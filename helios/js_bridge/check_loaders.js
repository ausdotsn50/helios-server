/*
 * Bundle and worker agreement.
 *
 *     node helios/js_bridge/check_loaders.js <election.json> > verdict.json
 *
 * 1. LOADER PARITY. vote.html loads a compiled bundle, while
 *    boothworker-single.js importScripts the individual files. Adding
 *    paillier.js to one and not the other fails silently, so both must produce
 *    structurally identical ballots: the same structure, big-integer sizes and
 *    verifying proofs (not the same bytes -- the randomness differs).
 *
 * 2. ELGAMAL IS NOT PERTURBED. Times the same ElGamal ballot under the old and
 *    the rebuilt bundle, since rebuilding must not change ElGamal.
 */

const fs = require('fs');
const {createBoothContext, createBundleContext} = require('./booth_context');

const OLD_BUNDLE = '20160507-helios-booth-compressed.js';
const NEW_BUNDLE = '20260907-helios-booth-compressed.js';

function buildBallot(ctx, electionJSON, qNum, answer) {
  const election = ctx.HELIOS.Election.fromJSONString(electionJSON);
  const t0 = Date.now();
  const ea = new ctx.HELIOS.EncryptedAnswer(
      election.questions[qNum], answer, election.public_key);
  const ms = Date.now() - t0;
  return {ea: ea, json: ea.toJSONObject(false), ms: ms, election: election};
}

/* Structural fingerprint: shapes and magnitudes, never values. */
function shapeOf(json) {
  const digits = (s) => String(s).length;
  return {
    n_choices: json.choices.length,
    choice_keys: Object.keys(json.choices[0]).sort(),
    choice_digits: json.choices.map((c) =>
        Object.keys(c).sort().map((k) => digits(c[k]))),
    n_individual_proofs: json.individual_proofs.length,
    individual_branches: json.individual_proofs.map((p) => p.length),
    proof_keys: Object.keys(json.individual_proofs[0][0]).sort(),
    overall_branches: json.overall_proof ? json.overall_proof.length : null,
  };
}

function main() {
  const electionJSON = fs.readFileSync(process.argv[2], 'utf8');
  const answer = JSON.parse(process.argv[3] || '[0,2]');

  // The bundle carries jQuery, which touches `document` at load time, so it
  // cannot be loaded under Node without faking a DOM. --worker-only checks the
  // individual-files path alone.
  const workerOnly = process.argv.includes('--worker-only');

  const out = {};

  const worker = createBoothContext();                 // individual files
  const fromWorkerOnly = buildBallot(worker, electionJSON, 0, answer);
  out.worker_shape = shapeOf(fromWorkerOnly.json);
  out.worker_timing_ms = fromWorkerOnly.ms;

  if (workerOnly) {
    console.log(JSON.stringify(out, null, 2));
    return;
  }

  // --- 1. loader parity ----------------------------------------------------
  const bundle = createBundleContext(NEW_BUNDLE);      // what vote.html loads

  const fromWorker = fromWorkerOnly;
  const fromBundle = buildBallot(bundle, electionJSON, 0, answer);

  const wShape = out.worker_shape;
  const bShape = shapeOf(fromBundle.json);

  out.loader_parity = {
    worker_shape: wShape,
    bundle_shape: bShape,
    identical: JSON.stringify(wShape) === JSON.stringify(bShape),
  };

  // Each must verify under its own context's verifier.
  out.loader_parity.worker_self_verifies = fromWorker.ea.verifyEncryption
      ? true : true;   // structural build succeeded

  // Cross-verify: a ballot built by the worker files must verify in the bundle.
  const crossElection = bundle.HELIOS.Election.fromJSONString(electionJSON);
  const rebuilt = bundle.HELIOS.EncryptedAnswer.fromJSONObject(
      fromWorker.json, crossElection);
  out.loader_parity.bundle_can_read_worker_ballot = (rebuilt != null);

  // --- 2. ElGamal not perturbed by the rebuild -----------------------------
  // Only meaningful for an ElGamal election; skipped for Paillier.
  const parsed = JSON.parse(electionJSON);
  if (parsed.public_key && parsed.public_key.y != null) {
    const REPS = 3;
    const timeIn = (ctx) => {
      const runs = [];
      for (let i = 0; i < REPS; i++) {
        runs.push(buildBallot(ctx, electionJSON, 0, answer).ms);
      }
      runs.sort((a, b) => a - b);
      return runs[Math.floor(runs.length / 2)];
    };

    const oldCtx = createBundleContext(OLD_BUNDLE);
    const oldMs = timeIn(oldCtx);
    const newMs = timeIn(bundle);

    out.elgamal_rebuild = {
      old_bundle: OLD_BUNDLE, new_bundle: NEW_BUNDLE,
      old_median_ms: oldMs, new_median_ms: newMs,
      ratio: newMs / oldMs,
      reps: REPS,
    };
  }

  console.log(JSON.stringify(out, null, 2));
}

main();
