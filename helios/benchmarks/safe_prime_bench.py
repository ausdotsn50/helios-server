"""
Safe-prime generation micro-benchmark: choosing the sieve bound B, and what the
sieved search buys over the generator it replaced.

    uv run python manage.py shell -c "exec(open('helios/benchmarks/safe_prime_bench.py').read())"

Three parts:

  1. Choosing B. On one shared set of random 1024-bit candidates (p' = 6k+5,
     p = 2p'+1, exactly as generate_safe_prime draws them), time the joint gcd
     against the product of the odd primes up to B, and the base-2 Fermat test
     on each survivor. How many candidates a safe prime takes does not depend
     on B, so the expected cost per candidate ranks the bounds exactly -- more
     precisely than timing whole searches, whose length is roughly geometric
     and needs far more runs to average out.

     The share of candidates that survive the gcd is not left to sampling:
     for a uniform p' = 5 (mod 6), each prime q >= 5 divides p' or 2p'+1 with
     probability 2/q, independently, so the expected share is exactly the
     product of (q-2)/q over the sieve primes. The measured share is printed
     beside it as a check; the cost uses the exact one.
  2. The generator as shipped, at 1024 bits (the DJN key size): median and
     range over runs.
  3. Old against new at 512 bits. The old algorithm -- a fresh (bits-1)-bit
     probable prime p' per attempt from pycryptodome, then a test of 2p'+1 --
     is kept as a private copy HERE ONLY, so the comparison runs the code that
     was replaced rather than a description of it. It is not run at 1024 bits:
     that takes minutes per prime (.cache/after_phase2.log records one run).

Written to be exec'd by `manage.py shell`: it runs top to bottom and is not
meant to be imported.
"""

import math
import secrets
import statistics
import time

from Crypto.Math import Primality

from helios.crypto import paillier

SWEEP_BOUNDS = (1 << 12, 1 << 13, 1 << 14, 1 << 15, 1 << 16)
SWEEP_BITS = 1024
SWEEP_CANDIDATES = 20000
RUNS_1024 = 10
RUNS_512 = 7


def _old_generate_safe_prime(bits):
  """The generator this benchmark's subject replaced, verbatim."""
  min_p = math.isqrt(1 << (2 * bits - 1)) + 1     # > sqrt(2) * 2^(bits-1)

  # pycryptodome Integers multiply by an int on the left only
  while True:
    p_prime = Primality.generate_probable_prime(
      exact_bits=bits - 1, prime_filter=lambda c: c * 2 + 1 >= min_p)
    p = p_prime * 2 + 1
    if Primality.test_probable_prime(p) == Primality.PROBABLY_PRIME:
      return int(p)


def _candidates(bits, count):
  """Uniform candidates p' = 6k + 5 with p = 2p'+1 in [min_p, 2^bits)."""
  min_p = math.isqrt(1 << (2 * bits - 1)) + 1
  k_lo = -(-(min_p - 11) // 12)
  k_hi = ((1 << bits) - 12) // 12
  out = []
  for _ in range(count):
    p_prime = 6 * (k_lo + secrets.randbelow(k_hi - k_lo + 1)) + 5
    out.append((p_prime, 2 * p_prime + 1))
  return out


def _seconds(fn, runs, label):
  ts = []
  for i in range(runs):
    t0 = time.perf_counter()
    fn()
    ts.append(time.perf_counter() - t0)
    print('  %s %d/%d: %.2f s' % (label, i + 1, runs, ts[-1]), flush=True)
  return ts


def _summary(ts):
  return '%7.2f s   (%.2f-%.2f)' % (statistics.median(ts), min(ts), max(ts))


def main():
  print('Safe-prime generation -- Python, this machine\n', flush=True)

  # --- 1. choosing B -------------------------------------------------------
  print('1. Sieve bound B: expected cost per candidate at %d bits, on %d '
        'shared candidates' % (SWEEP_BITS, SWEEP_CANDIDATES), flush=True)

  cands = _candidates(SWEEP_BITS, SWEEP_CANDIDATES)
  t0 = time.perf_counter_ns()
  _candidates(SWEEP_BITS, SWEEP_CANDIDATES)
  draw_us = (time.perf_counter_ns() - t0) / SWEEP_CANDIDATES / 1e3

  rows = []
  for bound in SWEEP_BOUNDS:
    primes = paillier._odd_primes_up_to(bound)
    product = math.prod(primes)
    exact = math.prod((q - 2) / q for q in primes if q >= 5)

    t0 = time.perf_counter_ns()
    survivors = [(q, p) for q, p in cands if math.gcd(q * p, product) == 1]
    gcd_us = (time.perf_counter_ns() - t0) / len(cands) / 1e3

    t0 = time.perf_counter_ns()
    for _q, p in survivors:
      pow(2, p - 1, p)
    fermat_ms = ((time.perf_counter_ns() - t0) / max(len(survivors), 1) / 1e6)

    measured = len(survivors) / len(cands)
    per_candidate_us = draw_us + gcd_us + exact * fermat_ms * 1e3
    rows.append((bound, product.bit_length(), gcd_us, exact, measured,
                 fermat_ms, per_candidate_us))

  best = min(rows, key=lambda r: r[-1])
  print('  %-7s %7s %8s %15s %10s %15s' % ('B', 'M bits', 'gcd us',
                                        'survive (meas)', 'Fermat ms',
                                        'us / candidate'))
  for bound, m_bits, gcd_us, exact, measured, fermat_ms, per in rows:
    mark = '  <- lowest' if bound == best[0] else ''
    print('  2^%-5d %7d %8.1f %6.2f%% (%.2f%%) %10.2f %15.1f%s'
          % (bound.bit_length() - 1, m_bits, gcd_us, 100 * exact,
             100 * measured, fermat_ms, per, mark))
  print('  (drawing a candidate: %.1f us, included in every row)' % draw_us)
  print('  in use: B = 2^%d (paillier._SIEVE_BOUND)\n'
        % (paillier._SIEVE_BOUND.bit_length() - 1), flush=True)

  # --- 2. the generator as shipped, at the DJN key size ---------------------
  print('2. generate_safe_prime(1024), %d runs' % RUNS_1024, flush=True)
  new_1024 = _seconds(lambda: paillier.generate_safe_prime(1024), RUNS_1024,
                      'new 1024')

  # --- 3. old against new, at 512 bits --------------------------------------
  print('\n3. Old against new at 512 bits, %d runs each' % RUNS_512,
        flush=True)
  new_512 = _seconds(lambda: paillier.generate_safe_prime(512), RUNS_512,
                     'new 512')
  old_512 = _seconds(lambda: _old_generate_safe_prime(512), RUNS_512,
                     'old 512')

  print('\nSafe-prime generation -- Python, this machine; median (min-max)')
  print('  B = 2^%d; lowest measured cost per candidate: B = 2^%d'
        % (paillier._SIEVE_BOUND.bit_length() - 1, best[0].bit_length() - 1))
  print('  new, 1024 bits  %s   %d runs' % (_summary(new_1024), RUNS_1024))
  print('  new,  512 bits  %s   %d runs' % (_summary(new_512), RUNS_512))
  print('  old,  512 bits  %s   %d runs' % (_summary(old_512), RUNS_512))
  print('  old / new at 512 bits, by median: %.1fx'
        % (statistics.median(old_512) / statistics.median(new_512)))


main()
