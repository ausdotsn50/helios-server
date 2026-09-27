/*
 * Load Helios's own booth cryptography under Node.
 *
 * Test 9 (cross-implementation agreement) needs to run the SAME JavaScript a
 * voter's browser runs, not a reimplementation of it. These files are plain
 * scripts that communicate through globals, so they are evaluated into one
 * shared vm context in the order boothworker-single.js importScripts them.
 *
 * Location note: build spec §7 asks for this shim under helios/tests/js_bridge/.
 * It is here instead because helios/tests.py already exists as a module, and a
 * helios/tests/ package would shadow it and break the upstream suite.
 *
 * Nothing in heliosbooth/ is modified to accommodate Node. The handful of
 * browser globals the booth touches are stubbed here, so the measured code path
 * stays exactly the one that ships.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const BOOTH = path.resolve(__dirname, '..', '..', 'heliosbooth');

// The load order boothworker-single.js uses. underscore first, because
// elgamal.js and paillier.js both call _() at definition time.
const SCRIPTS = [
  'js/underscore-min.js',
  'js/jscrypto/jsbn.js',
  'js/jscrypto/jsbn2.js',
  'js/jscrypto/sjcl.js',
  'js/jscrypto/class.js',
  'js/jscrypto/bigint.js',
  'js/jscrypto/random.js',
  'js/jscrypto/elgamal.js',
  'js/jscrypto/paillier.js',
  'js/jscrypto/scheme_adapters.js',
  'js/jscrypto/sha1.js',
  'js/jscrypto/sha2.js',
  'js/jscrypto/helios.js',
];

/*
 * A fresh global for the booth's scripts.
 *
 * DONT_CONTEXTIFY gives the context an ORDINARY global object. A default,
 * contextified sandbox routes every global lookup through an interceptor, and
 * jsbn resolves its helpers as globals inside its inner loops: measured here,
 * one modPow at a 2048-bit modulus with a 1024-bit exponent took ~2.1 s in a
 * sandbox and ~56 ms with an ordinary global -- the difference between a
 * 1024-bit test key being usable or not. The booth code runs unchanged either
 * way; only the host's lookup path differs. A Node without the constant
 * (before 22.8) gets a contextified empty object: correct, just slow.
 */
function createGlobal() {
  const g = vm.createContext(vm.constants && vm.constants.DONT_CONTEXTIFY);

  // Browser globals the booth reaches for. Kept minimal on purpose: every
  // stub is a place where Node and the browser could diverge, so the list
  // should stay short enough to audit.
  g.window = g;
  g.self = g;
  g.navigator = {appName: 'node', userAgent: 'node'};
  g.console = console;
  g.setInterval = () => 0;
  g.clearInterval = () => {};
  g.setTimeout = setTimeout;

  return g;
}

function createBoothContext(extraScripts) {
  const context = createGlobal();

  for (const rel of SCRIPTS.concat(extraScripts || [])) {
    const file = path.join(BOOTH, rel);
    const code = fs.readFileSync(file, 'utf8');
    try {
      vm.runInContext(code, context, {filename: file});
    } catch (e) {
      throw new Error(`failed loading ${rel}: ${e.message}`);
    }
  }

  // Seed sjcl's generator, or Random.getRandomInteger throws
  // "generator isn't seeded".
  //
  // This mirrors what the booth itself does rather than replacing it:
  // vote.html:390 calls sjcl.random.addEntropy with randomness fetched from the
  // server, then vote.html:426 calls startCollectors for mouse/keyboard entropy.
  // Node has no DOM to collect from, so the server-randomness half is supplied
  // from crypto.randomBytes. The generator, the reduction and every consumer
  // stay exactly the ones that ship.
  const seed = require('crypto').randomBytes(128);
  const words = [];
  for (let i = 0; i < seed.length; i += 4) {
    words.push(seed.readInt32BE(i));
  }
  context.sjcl.random.addEntropy(words, 1024, 'node-crypto');

  return context;
}

/*
 * Load a compiled booth bundle instead of the individual files.
 *
 * This distinction is not cosmetic. heliosbooth/vote.html has every individual
 * <script> tag commented out and loads one concatenated bundle, while
 * boothworker-single.js importScripts the individual files. The measurement
 * harness drives the MAIN THREAD via /booth/vote.html, so it exercises the
 * bundle; a real voter's encryption runs in the WORKER, off the individual
 * files. Adding paillier.js to one and not the other fails silently, and which
 * half you notice depends on whether you test through the harness or the booth.
 */
function createBundleContext(bundleName) {
  const context = createGlobal();
  const file = path.join(BOOTH, 'js', bundleName);
  vm.runInContext(fs.readFileSync(file, 'utf8'), context, {filename: file});

  const seed = require('crypto').randomBytes(128);
  const words = [];
  for (let i = 0; i < seed.length; i += 4) {
    words.push(seed.readInt32BE(i));
  }
  context.sjcl.random.addEntropy(words, 1024, 'node-crypto');

  return context;
}

module.exports = {createBoothContext, createBundleContext, BOOTH};
