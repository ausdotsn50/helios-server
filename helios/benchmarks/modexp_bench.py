"""
Milestone B2a — modular-exponentiation microbenchmark (build spec §9).

    uv run python -m helios.benchmarks.modexp_bench [--samples 30] [--json out.json]

Why this runs BEFORE the proof layer
------------------------------------
The masterplan's §5 cost model predicts Paillier encryption at 13.7x ElGamal and
CRT decryption at 6.2x, with CRT itself worth 3.9x. Those numbers currently rest
on a derivation, not a measurement, and they drive both the sweep design and one
manuscript conclusion. Measuring them costs minutes; discovering they are wrong
after B3-B9 are built on them costs the sweep.

The model
---------
Wall-clock times can be argued about; modexp counts at stated operand widths
cannot. The unit is

    U = one modexp at a 2048-bit modulus with a 256-bit exponent

chosen because ElGamal-Helios never uses a 2048-bit exponent: every exponent in
the ElGamal path is drawn from Z_q with q of 256 bits (views.py:46 is a 77-digit
constant). An earlier project document scored ElGamal encryption as "2 modexps
@ 2048/2048" and thereby understated Paillier's disadvantage eightfold,
inverting one of its conclusions. That error is the reason this benchmark exists.

Modexp cost scales as (modulus bits)^2 x (exponent bits), so one Paillier
exponentiation should cost (4096/2048)^2 x (2048/256) = 4 x 8 = 32 U. The
benchmark checks that scaling law directly rather than assuming it.

Per-slot operation counts, read off the actual call graphs:

  ElGamal   ElGamal.encrypt        2 modexp (2048, 256)
            Proof.generate         2 modexp (2048, 256)
            Proof.simulate         2 modexp (2048, 256) + 2 modexp (2048, 160)
                                 = 6 x (2048,256) + 2 x (2048,160)  = 7.25 U

  Paillier  v^n                    1 modexp (4096, 2048)
            real a = r^n           1 modexp (4096, 2048)
            simulated a            2 modexp (4096, 2048) / (4096, 160)
            response v^e mod n     1 modexp (2048, 160)
                                 = 3 x (4096,2048) + 1 x (4096,160)
                                   + 1 x (2048,160)                 = 99.1 U

Paillier does FOUR exponentiations per slot where ElGamal does EIGHT -- Pi_root's
commitment is one value where Chaum-Pedersen's is two -- and still loses, because
operand and exponent width dominate the count advantage. That shape, not just the
number, is what the manuscript should predict and then confirm.
"""

import argparse
import json
import statistics
import sys
import time

from Crypto.Util import number

# Predictions under test (masterplan §5.1). Reported alongside the measurement
# so a disagreement is visible rather than quietly absorbed.
PREDICTED = {
  'encryption_ratio': 13.7,
  'decryption_ratio_with_crt': 6.2,
  'crt_speedup': 3.9,
}

# Build spec §9: if measurement and prediction differ by more than this, stop and
# report before B3 -- the sweep design and a manuscript conclusion depend on them.
TOLERANCE = 0.25


def _time_op(fn, samples):
  """Median and IQR in nanoseconds. Median, not mean: one GC pause should not
  move the headline number."""
  timings = []
  for _ in range(samples):
    t0 = time.perf_counter_ns()
    fn()
    timings.append(time.perf_counter_ns() - t0)

  timings.sort()
  q1, q3 = statistics.quantiles(timings, n=4)[0], statistics.quantiles(timings, n=4)[2]
  return {
    'median_ns': statistics.median(timings),
    'iqr_ns': q3 - q1,
    'min_ns': timings[0],
    'max_ns': timings[-1],
    'samples': samples,
  }


def build_operands():
  """
  Real operands at the real widths. Random values rather than structured ones:
  modexp timing is data-dependent, and a value with an unusual bit pattern would
  flatter or penalise one arm.
  """
  from helios.views import ELGAMAL_PARAMS
  from helios.crypto import paillier

  # ElGamal: the actual production parameters, not a synthetic 2048-bit prime.
  eg_p, eg_q, eg_g = ELGAMAL_PARAMS.p, ELGAMAL_PARAMS.q, ELGAMAL_PARAMS.g
  eg_exp_256 = number.getRandomRange(1, eg_q)
  eg_exp_160 = number.getRandomNBitInteger(160)

  # Paillier: a real 2048-bit modulus.
  kp = paillier.Paillier(key_size=1024).generate_keypair()
  n, n2 = kp.pk.n, kp.pk.n2
  p = kp.sk.p
  v = paillier.random_z_star_n(n)
  u = number.getRandomRange(1, n2)
  pa_exp_160 = number.getRandomNBitInteger(160)

  return {
    'elgamal': {'p': eg_p, 'q': eg_q, 'g': eg_g,
                'e256': eg_exp_256, 'e160': eg_exp_160},
    'paillier': {'n': n, 'n2': n2, 'p': p, 'v': v, 'u': u,
                 'e160': pa_exp_160, 'keypair': kp},
  }


def run(samples=30):
  ops = build_operands()
  eg, pa = ops['elgamal'], ops['paillier']

  results = {}

  # --- the four primitives build spec §9 names -----------------------------

  results['elgamal_encrypt_modexp'] = _time_op(
    lambda: pow(eg['g'], eg['e256'], eg['p']), samples)
  results['elgamal_encrypt_modexp']['operands'] = '2048-bit p, 256-bit exponent'

  results['paillier_v_pow_n'] = _time_op(
    lambda: pow(pa['v'], pa['n'], pa['n2']), samples)
  results['paillier_v_pow_n']['operands'] = '4096-bit n^2, 2048-bit exponent'

  results['paillier_crt_half'] = _time_op(
    lambda: pow(pa['u'], pa['p'] - 1, pa['p'] * pa['p']), samples)
  results['paillier_crt_half']['operands'] = '2048-bit p^2, 1024-bit exponent'

  results['pi_root_response'] = _time_op(
    lambda: pow(pa['v'], pa['e160'], pa['n']), samples)
  results['pi_root_response']['operands'] = '2048-bit n, 160-bit exponent'

  # Two more the per-slot composites need.
  results['elgamal_simulate_modexp_160'] = _time_op(
    lambda: pow(eg['g'], eg['e160'], eg['p']), samples)
  results['elgamal_simulate_modexp_160']['operands'] = '2048-bit p, 160-bit exponent'

  results['paillier_a_pow_e'] = _time_op(
    lambda: pow(pa['u'], pa['e160'], pa['n2']), samples)
  results['paillier_a_pow_e']['operands'] = '4096-bit n^2, 160-bit exponent'

  # --- the scaling law itself ---------------------------------------------
  # (modulus bits)^2 x (exponent bits) predicts 32x between these two.
  measured_32x = (results['paillier_v_pow_n']['median_ns'] /
                  results['elgamal_encrypt_modexp']['median_ns'])

  # --- composites, from measured primitives -------------------------------
  eg_slot = (6 * results['elgamal_encrypt_modexp']['median_ns'] +
             2 * results['elgamal_simulate_modexp_160']['median_ns'])
  pa_slot = (3 * results['paillier_v_pow_n']['median_ns'] +
             1 * results['paillier_a_pow_e']['median_ns'] +
             1 * results['pi_root_response']['median_ns'])

  # --- CRT, measured directly against the real implementation -------------
  # Not derived: both decryption paths exist, so this is the actual ablation.
  from helios.crypto import paillier
  kp = pa['keypair']
  ct = kp.pk.encrypt(paillier.PaillierPlaintext(12345, kp.pk))

  results['paillier_decrypt_crt'] = _time_op(
    lambda: kp.sk.decryption_factor(ct), samples)
  results['paillier_decrypt_no_crt'] = _time_op(
    lambda: kp.sk.decrypt_no_crt(ct), samples)

  eg_dec = results['elgamal_encrypt_modexp']['median_ns']  # alpha^x, (2048,256)

  measured = {
    'modexp_scaling_32x': measured_32x,
    'encryption_ratio': pa_slot / eg_slot,
    'crt_speedup': (results['paillier_decrypt_no_crt']['median_ns'] /
                    results['paillier_decrypt_crt']['median_ns']),
    'decryption_factor_ratio_with_crt':
      results['paillier_decrypt_crt']['median_ns'] / eg_dec,
    'elgamal_slot_ns': eg_slot,
    'paillier_slot_ns': pa_slot,
  }

  return {'primitives': results, 'derived': measured, 'predicted': PREDICTED,
          'samples': samples}


def report(out):
  p, d = out['primitives'], out['derived']

  print('\nMODEXP PRIMITIVES  (median, IQR over %d samples)' % out['samples'])
  print('-' * 78)
  for name in ('elgamal_encrypt_modexp', 'elgamal_simulate_modexp_160',
               'paillier_v_pow_n', 'paillier_a_pow_e', 'paillier_crt_half',
               'pi_root_response'):
    r = p[name]
    print(f'  {name:32s} {r["median_ns"]/1e6:8.3f} ms  '
          f'IQR {r["iqr_ns"]/1e6:6.3f}   {r["operands"]}')

  print('\nDECRYPTION (real implementation, not derived)')
  print('-' * 78)
  for name in ('paillier_decrypt_crt', 'paillier_decrypt_no_crt'):
    r = p[name]
    print(f'  {name:32s} {r["median_ns"]/1e6:8.3f} ms  '
          f'IQR {r["iqr_ns"]/1e6:6.3f}')

  print('\nMEASURED vs PREDICTED')
  print('-' * 78)
  print(f'  {"quantity":32s} {"measured":>10s} {"predicted":>10s} {"delta":>9s}')

  verdicts = []
  for key, label in (('encryption_ratio', 'encryption ratio (per slot)'),
                     ('crt_speedup', 'CRT speedup on decryption')):
    m, pr = d[key], out['predicted'][key]
    delta = (m - pr) / pr
    flag = 'OK' if abs(delta) <= TOLERANCE else 'OUT OF TOLERANCE'
    verdicts.append((label, flag, delta))
    print(f'  {label:32s} {m:10.2f} {pr:10.2f} {delta:+8.1%}  {flag}')

  print(f'\n  {"modexp scaling law (expect 32x)":32s} '
        f'{d["modexp_scaling_32x"]:10.2f} {32.0:10.2f} '
        f'{(d["modexp_scaling_32x"] - 32) / 32:+8.1%}')
  print(f'  {"Paillier dec.factor / ElGamal":32s} '
        f'{d["decryption_factor_ratio_with_crt"]:10.2f}'
        f'{"  (proof layer lands at B3)":>21s}')

  bad = [v for v in verdicts if v[1] != 'OK']
  print()
  if bad:
    print('  STOP AND REPORT BEFORE B3 (build spec §9): '
          + ', '.join(f'{lbl} off by {dl:+.1%}' for lbl, _, dl in bad))
  else:
    print('  All ratios within +/-%d%% of prediction — B3 may proceed.'
          % int(TOLERANCE * 100))
  return 0 if not bad else 1


def main(argv=None):
  import os
  import django
  os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')
  django.setup()

  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument('--samples', type=int, default=30)
  ap.add_argument('--json', default=None, help='also write raw results here')
  args = ap.parse_args(argv)

  out = run(samples=args.samples)

  if args.json:
    with open(args.json, 'w') as f:
      json.dump(out, f, indent=2)
    print(f'raw results -> {args.json}')

  return report(out)


if __name__ == '__main__':
  sys.exit(main())
