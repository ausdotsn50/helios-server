"""
DJN §4.1 modes micro-benchmark: what each encryption function costs per
ciphertext, and what it costs up front.

    uv run python manage.py shell -c "exec(open('helios/benchmarks/djn41_modes_bench.py').read())"

At a real 2048-bit key per mode, it prints medians (with the range) of:

  - key generation, 5 runs per mode. 'off' draws two 1024-bit strong primes.
    'short' and 'long' draw two 1024-bit SAFE primes, at a median of 12 s
    each with generate_safe_prime and a tail into tens of seconds, so this
    part runs for several minutes;
  - the one-time build of the fixed-base tables, 30 runs;
  - the ciphertext step for one choice, 30 runs: the blinding factor plus the
    Pi_root witness it implies --

        off     (1 + m*n) * v^n mod n^2; the witness is v itself, free
        short   (1 + m*n) * hn^a mod n^2 and h^a mod n, from the tables
        long    the same, with a from [0, n/2) instead of [0, 2^1024)
        long    the same computed with pow() instead of the tables, as a
                reference for what the tables are worth

Python on this machine, and the ciphertext step only: the proofs, which
dominate the cost of encrypting a ballot, are not included, and neither is
the booth's JavaScript. Timing instrumentation of the real pipeline is a
separate phase.

Written to be exec'd by `manage.py shell`: it runs top to bottom and is not
meant to be imported.
"""

import statistics
import time

from helios.crypto import paillier

KEYGEN_RUNS = 5
RUNS = 30
LABEL = 'Python, this machine, ciphertext step only (proofs not included)'


def _timings_ms(fn, runs, progress=None):
  timings = []
  for i in range(runs):
    t0 = time.perf_counter_ns()
    fn()
    timings.append((time.perf_counter_ns() - t0) / 1e6)
    if progress:
      print('  %s %d/%d: %.1f s' % (progress, i + 1, runs, timings[-1] / 1e3),
            flush=True)
  return timings


def _summary(timings, unit='ms'):
  scale = 1e3 if unit == 's' else 1
  median, low, high = (statistics.median(timings) / scale,
                       min(timings) / scale, max(timings) / scale)
  return '%9.1f %s   (%.1f-%.1f)' % (median, unit, low, high)


def _keygen(mode):
  """KEYGEN_RUNS timings for this mode, and the last key they produced."""
  made = []

  def generate():
    made.append(paillier.Paillier(key_size=1024,
                                  djn41_mode=mode).generate_keypair())

  timings = _timings_ms(generate, KEYGEN_RUNS, progress='keygen %s' % mode)
  return timings, made[-1]


def _ciphertext_step(pk, rs, use_tables=True):
  """
  RUNS timings of blinding + witness for one choice, one fresh r per run.

  Through the real API -- encrypt_with_r and proof_witness -- except for the
  no-tables reference, which computes the same two values with pow() and is
  checked once against the API.
  """
  m = paillier.PaillierPlaintext(1, pk)
  n, n2 = pk.n, pk.n2
  queue = list(rs)

  if use_tables:
    def step():
      r = queue.pop()
      pk.encrypt_with_r(m, r)
      pk.proof_witness(r)
  else:
    r0 = rs[0]
    assert ((1 + n) * pow(pk.hn, r0, n2) % n2 == pk.encrypt_with_r(m, r0).c
            and pow(pk.h, r0, n) == pk.proof_witness(r0))

    def step():
      r = queue.pop()
      (1 + n) * pow(pk.hn, r, n2) % n2
      pow(pk.h, r, n)

  return _timings_ms(step, RUNS)


def main():
  print('DJN §4.1 modes -- %s' % LABEL, flush=True)
  print('Key generation takes a while: %d runs per mode, with safe primes in '
        'the two DJN modes.\n' % KEYGEN_RUNS, flush=True)

  keygen, keys = {}, {}
  for mode in paillier.DJN41_MODES:
    keygen[mode], keys[mode] = _keygen(mode)

  tables = {}
  for mode in ('short', 'long'):
    pk = keys[mode].pk

    def build():
      pk._tables = None
      pk.fixed_base_tables()

    tables[mode] = _timings_ms(build, RUNS)

  steps = {}
  for label, mode, use_tables in (('off', 'off', True),
                                  ('short, tables', 'short', True),
                                  ('long, tables', 'long', True),
                                  ('long, pow()', 'long', False)):
    pk = keys[mode].pk
    rs = [pk.random_randomness() for _ in range(RUNS)]
    if pk.uses_djn_41:
      pk.fixed_base_tables()    # built before timing, as it is in use
    steps[label] = _ciphertext_step(pk, rs, use_tables)

  n_bits = keys['off'].pk.n.bit_length()
  print('\nDJN §4.1 modes -- %s' % LABEL)
  print('|n| = %d bits for every key; medians over the runs, (min-max)\n'
        % n_bits)

  print('Key generation, %d runs per mode' % KEYGEN_RUNS)
  print('  off     strong primes         %s' % _summary(keygen['off'], 's'))
  for mode in ('short', 'long'):
    print('  %-7s safe primes, h, hn    %s' % (mode, _summary(keygen[mode], 's')))

  print('\nFixed-base tables, one-time build per key, %d runs' % RUNS)
  for mode in ('short', 'long'):
    T_hn, T_h = keys[mode].pk.fixed_base_tables()
    print('  %-7s %4d + %4d entries   %s'
          % (mode, len(T_hn), len(T_h), _summary(tables[mode])))

  off = statistics.median(steps['off'])
  print('\nCiphertext step: blinding + witness for one choice, %d runs' % RUNS)
  for label in steps:
    median = statistics.median(steps[label])
    print('  %-14s %s   %5.2fx off' % (label, _summary(steps[label]),
                                        off / median))

  print('\nTables pay for their one-time build after this many ciphertexts:')
  for mode in ('short', 'long'):
    saved = off - statistics.median(steps['%s, tables' % mode])
    if saved > 0:
      print('  %-7s %.1f' % (mode, statistics.median(tables[mode]) / saved))
    else:
      print('  %-7s never: no faster than off' % mode)


main()
