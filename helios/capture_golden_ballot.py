"""
Capture the ElGamal golden-ballot baseline (build spec §7, test 15).

    uv run python -m helios.capture_golden_ballot

Run this ONLY on a tree whose ElGamal path is known-good — in practice, at
milestone B0, before the first Paillier change. The fixture it writes is the
reference that every later commit is compared against, so capturing it from an
already-modified tree would bake the modification into the baseline and the
guard would pass forever while proving nothing.

If test 15 fails later, the fix is to find what changed in the ElGamal path.
It is never to re-run this script.
"""

import os
import sys


def main():
  import django
  os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')
  django.setup()

  from helios import utils
  from helios.tests_paillier import build_golden_elgamal_ballot, GOLDEN_PATH

  if os.path.exists(GOLDEN_PATH) and '--force' not in sys.argv:
    print(f'refusing to overwrite {GOLDEN_PATH}\n'
          f'  A baseline already exists. Overwriting it would silently redefine\n'
          f'  what "unchanged" means. Pass --force only if you are certain the\n'
          f'  existing baseline was captured from a bad tree.')
    return 1

  payload = utils.to_json(build_golden_elgamal_ballot())

  os.makedirs(os.path.dirname(GOLDEN_PATH), exist_ok=True)
  with open(GOLDEN_PATH, 'w') as f:
    f.write(payload)

  print(f'wrote {GOLDEN_PATH}  ({len(payload)} bytes)')
  return 0


if __name__ == '__main__':
  sys.exit(main())
