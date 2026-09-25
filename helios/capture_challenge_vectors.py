"""
Generate helios/fixtures/challenge_vectors.json (build spec §6.1, milestone B1).

    uv run python -m helios.capture_challenge_vectors

Expected values come from the Python implementation in helios/crypto/paillier.py;
the JavaScript implementation must then reproduce every one, under Node and in
Chrome. Any mismatch stops the build until resolved -- this is the single
cheapest way to discover the plan is wrong, and "fix it later" is how a proof
layer ends up verifying in the browser and failing at cast time.

Case selection is adversarial rather than representative. The failure modes worth
provoking are all about string formatting, so the vectors probe: list lengths
L = 1, 2 and 13 (the real ballot's two overall-proof widths, plus the
single-commitment wrapper); operand sizes from one digit to 1234 (a full value
mod n^2); a = 1, the smallest legal commitment; leading digits 1 and 9, which
differ in whether a naive implementation might pad; and a value with an interior
run of zeros, which catches radix confusion.
"""

import os
import sys


def build_vectors():
  from helios.crypto.paillier import paillier_disjunctive_challenge_generator

  # Deterministic, and deliberately not random: a fixture whose inputs change
  # between runs cannot pin two implementations to each other.
  one_digit = 1
  nine_leading = 9
  small = 2
  interior_zeros = 10 ** 20 + 1          # 1 followed by zeros then 1
  mid = 12345678901234567890123456789
  # 617 decimal digits ~ a value mod n at |n| = 2048
  mod_n_sized = int('1' + '0123456789' * 61 + '01234')
  # 1234 decimal digits ~ a value mod n^2 at |n^2| = 4096
  mod_n2_sized = int('9' + '8765432109' * 123 + '876')

  cases = [
    ('L=1, a=1 (smallest legal commitment)', [one_digit]),
    ('L=1, single digit 9 (leading digit 9)', [nine_leading]),
    ('L=1, value mod n^2 (1234 digits)', [mod_n2_sized]),
    ('L=2, individual proof width', [one_digit, small]),
    ('L=2, both operands full width', [mod_n_sized, mod_n2_sized]),
    ('L=2, leading 1 then leading 9', [mid, nine_leading]),
    ('L=2, interior zeros', [interior_zeros, small]),
    ('L=3, mixed widths', [one_digit, mod_n_sized, mod_n2_sized]),
    ('L=13, Q1 overall-proof width (max 12)',
     [i + 1 for i in range(13)]),
    ('L=13, full-width operands',
     [mod_n2_sized - i for i in range(13)]),
    ('L=13, alternating tiny and huge',
     [(1 if i % 2 else mod_n_sized) for i in range(13)]),
    ('L=4, ascending magnitudes',
     [1, 12, 123456789, mod_n_sized]),
    ('L=2, adjacent values (differ in last digit only)',
     [mod_n2_sized, mod_n2_sized - 1]),
    ('L=1, value mod n (617 digits)', [mod_n_sized]),
  ]

  return [
    {
      'label': label,
      'commitments': [str(a) for a in commitments],
      'challenge': str(paillier_disjunctive_challenge_generator(commitments)),
    }
    for label, commitments in cases
  ]


def main():
  import django
  os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')
  django.setup()

  from helios import utils

  here = os.path.dirname(__file__)
  out_path = os.path.join(here, 'fixtures', 'challenge_vectors.json')

  vectors = build_vectors()
  payload = utils.to_json(vectors)

  os.makedirs(os.path.dirname(out_path), exist_ok=True)
  with open(out_path, 'w') as f:
    f.write(payload)

  print(f'wrote {out_path}  ({len(vectors)} vectors, {len(payload)} bytes)')
  widths = sorted({len(v['commitments']) for v in vectors})
  print(f'  list widths L: {widths}')
  digits = sorted({len(c) for v in vectors for c in v['commitments']})
  print(f'  operand digit lengths: {digits[0]}..{digits[-1]}')
  return 0


if __name__ == '__main__':
  sys.exit(main())
