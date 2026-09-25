"""
Milestone B8 — the ballot-size canary (masterplan §5.3).

    uv run python -m helios.benchmarks.ballot_size_canary [--scheme both]

Builds one ballot for the full 2025 NLE overseas face in a real headless Chrome,
through the compiled booth bundle -- the same artifact heliosbooth/vote.html
loads and the measurement harness drives -- and reports its serialized size.

WHY THIS IS A CANARY RATHER THAN A MEASUREMENT
----------------------------------------------
Ballot size is derivable from arithmetic on bit lengths, so it can be predicted
before it is measured. That makes it a cheap, high-signal correctness check on
the proof construction: if the measured Paillier ballot is not within 10% of
1,142 KiB, something is wrong -- most likely a branch count or a modulus mix-up.
A proof layer can be sound, verify correctly, and still have the wrong number of
branches; this catches that.

The target of 1,142 KiB supersedes IMPLEMENTATION_SPEC.md §2.6's 1.19 MiB, which
assumed a 256-bit challenge. Build spec §2.9 fixes t = 160, removing 29 decimal
digits from every proof branch. Using the old number would have raised a false
alarm here.

Encryption timing is reported alongside, but it is NOT the point of this script
and should not be cited as the encryption metric: one ballot is one sample, and
the harness measures encryption properly with a derived sample size.
"""

import argparse
import json
import pathlib
import sys
import time

# The 2025 NLE overseas ballot face. Q1 -> L = 13 branches, Q2 -> L = 2.
NLE_FACE = [
  {'short_name': 'senator', 'question': 'Vote for up to 12 Senators',
   'min': 0, 'max': 12,
   'answers': [f'Senator {i + 1}' for i in range(66)],
   'answer_urls': [None] * 66, 'choice_type': 'approval',
   'result_type': 'absolute', 'tally_type': 'homomorphic'},
  {'short_name': 'partylist', 'question': 'Vote for 1 Party-list group',
   'min': 0, 'max': 1,
   'answers': [f'Partylist {i + 1}' for i in range(156)],
   'answer_urls': [None] * 156, 'choice_type': 'approval',
   'result_type': 'absolute', 'tally_type': 'homomorphic'},
]

ANSWERS = [list(range(12)), [0]]        # a full 12-senator vote, one party-list

CANARY_TARGET_KIB = 1142.0
CANARY_TOLERANCE = 0.10

# Predictions under test (masterplan §5.3), reported alongside the measurement.
PREDICTED = {
  'elgamal_ballot_kib': 909.5,
  'paillier_ballot_kib': 1142.2,
  'ciphertext_ratio': 0.99,
  'ballot_ratio': 1.26,
  'elgamal_proof_share': 0.701,
  'paillier_proof_share': 0.764,
}


def _election_json(public_key_dict):
  return json.dumps({
    'public_key': public_key_dict, 'questions': NLE_FACE,
    'uuid': 'canary', 'name': 'canary', 'short_name': 'canary',
    'cast_url': '', 'description': '', 'frozen_at': None, 'openreg': False,
    'use_voter_aliases': False, 'voters_hash': None,
    'voting_ends_at': None, 'voting_starts_at': None,
  })


def build_elections():
  from helios import datatypes
  from helios.crypto import paillier
  from helios.views import ELGAMAL_PARAMS

  eg_pk = datatypes.LDObject.instantiate(
    ELGAMAL_PARAMS.generate_keypair().pk, datatype='legacy/EGPublicKey').toDict()
  pa_pk = paillier.Paillier(key_size=1024).generate_keypair().pk.to_dict()

  return {'elgamal': _election_json(eg_pk), 'paillier': _election_json(pa_pk)}


def measure(driver, election_json, label):
  totals = {'ciphertext_bytes': 0, 'proof_bytes': 0, 'timing_ms': 0.0}
  per_question = []

  for q_num, answer in enumerate(ANSWERS):
    r = driver.execute_script(
      'return window.__buildBallot(arguments[0], arguments[1], arguments[2])',
      election_json, q_num, answer)

    if not r['ok']:
      raise RuntimeError(f'{label} Q{q_num + 1} failed: {r["error"]}')

    for k in totals:
      totals[k] += r[k]
    per_question.append({
      'question': q_num + 1,
      'answers': len(NLE_FACE[q_num]['answers']),
      'L': NLE_FACE[q_num]['max'] - NLE_FACE[q_num]['min'] + 1,
      'ciphertext_kib': r['ciphertext_bytes'] / 1024,
      'proof_kib': r['proof_bytes'] / 1024,
      'timing_s': r['timing_ms'] / 1000,
    })

  total_bytes = totals['ciphertext_bytes'] + totals['proof_bytes']
  return {
    'label': label,
    'per_question': per_question,
    'ciphertext_kib': totals['ciphertext_bytes'] / 1024,
    'proof_kib': totals['proof_bytes'] / 1024,
    'ballot_kib': total_bytes / 1024,
    'proof_share': totals['proof_bytes'] / total_bytes,
    'encryption_s': totals['timing_ms'] / 1000,
  }


def main(argv=None):
  import os
  import django
  os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')
  django.setup()

  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument('--scheme', default='both',
                  choices=['both', 'elgamal', 'paillier'])
  ap.add_argument('--json', default=None)
  args = ap.parse_args(argv)

  from selenium import webdriver
  from selenium.webdriver.chrome.options import Options

  harness = pathlib.Path(__file__).resolve().parent.parent / 'js_bridge' \
      / 'bundle_harness.html'

  opts = Options()
  for flag in ('--headless=new', '--allow-file-access-from-files',
               '--no-sandbox', '--disable-dev-shm-usage'):
    opts.add_argument(flag)

  elections = build_elections()
  schemes = ['elgamal', 'paillier'] if args.scheme == 'both' else [args.scheme]

  driver = webdriver.Chrome(options=opts)
  # A full-face Paillier question takes minutes; the default 120 s HTTP read
  # timeout would abort it long before the script timeout ever fired.
  driver.command_executor.client_config.timeout = 3600
  driver.set_script_timeout(3600)

  results = {}
  try:
    driver.get(f'file://{harness}')
    if not driver.execute_script('return window.__loaded'):
      raise RuntimeError('bundle did not expose HELIOS/Paillier/CRYPTO — is '
                         'paillier.js in the bundle? See build spec §6.4')
    driver.execute_script('return window.__seed()')

    for scheme in schemes:
      t0 = time.time()
      results[scheme] = measure(driver, elections[scheme], scheme)
      results[scheme]['wall_s'] = time.time() - t0
  finally:
    driver.quit()

  report(results)

  if args.json:
    with open(args.json, 'w') as f:
      json.dump(results, f, indent=2)
    print(f'\nraw results -> {args.json}')

  if 'paillier' in results:
    delta = abs(results['paillier']['ballot_kib'] - CANARY_TARGET_KIB) \
        / CANARY_TARGET_KIB
    return 0 if delta <= CANARY_TOLERANCE else 1
  return 0


def report(results):
  print('\nBALLOT SIZE — 2025 NLE overseas face (66 max 12, 156 max 1)')
  print('-' * 78)

  for scheme, r in results.items():
    print(f'\n  {scheme}')
    for q in r['per_question']:
      print(f'    Q{q["question"]} ({q["answers"]:3d} answers, L={q["L"]:2d})  '
            f'{q["timing_s"]:7.1f}s   ct {q["ciphertext_kib"]:8.1f} KiB   '
            f'pf {q["proof_kib"]:9.1f} KiB')
    print(f'    BALLOT  {r["ballot_kib"]:9.1f} KiB    '
          f'proofs {100 * r["proof_share"]:.1f}%    '
          f'encryption {r["encryption_s"]:.1f}s')

  if 'paillier' in results:
    measured = results['paillier']['ballot_kib']
    delta = (measured - CANARY_TARGET_KIB) / CANARY_TARGET_KIB
    lo = CANARY_TARGET_KIB * (1 - CANARY_TOLERANCE)
    hi = CANARY_TARGET_KIB * (1 + CANARY_TOLERANCE)

    print(f'\n  B8 CANARY  measured {measured:.1f} KiB   '
          f'target {CANARY_TARGET_KIB:.0f} KiB +/-10% ({lo:.1f} - {hi:.1f})')
    print(f'             delta {delta:+.2%}  ->  '
          f'{"PASS" if abs(delta) <= CANARY_TOLERANCE else "FAIL"}')

  if len(results) == 2:
    eg, pa = results['elgamal'], results['paillier']
    print('\n  MEASURED vs PREDICTED (masterplan §5.3)')
    rows = [
      ('ciphertext ratio Pa/EG', pa['ciphertext_kib'] / eg['ciphertext_kib'],
       PREDICTED['ciphertext_ratio']),
      ('ballot ratio Pa/EG', pa['ballot_kib'] / eg['ballot_kib'],
       PREDICTED['ballot_ratio']),
      ('ElGamal proof share', eg['proof_share'],
       PREDICTED['elgamal_proof_share']),
      ('Paillier proof share', pa['proof_share'],
       PREDICTED['paillier_proof_share']),
    ]
    for label, got, pred in rows:
      print(f'    {label:26s} {got:8.3f}   predicted {pred:6.3f}   '
            f'{(got - pred) / pred:+7.1%}')

    print(f'\n    encryption ratio Pa/EG   {pa["encryption_s"] / eg["encryption_s"]:8.2f}x  '
          f'(in-browser jsbn; one ballot, not the encryption metric)')


if __name__ == '__main__':
  sys.exit(main())
