"""
Non-functional timing instrumentation.

Writes one JSON object per line to the path in HELIOS_MEASURE_PATH.
When that variable is unset, every function here is a no-op and Helios
behaves exactly as upstream -- this is the production default.

Records are keyed by election uuid. The harness creates exactly one
election per measurement cell, knows its uuid, and joins on it. The file
is therefore append-only and shared across runs: the web process and the
Celery worker are long-lived and read this path once at startup, so it
cannot be run-scoped.

Nothing here alters a ciphertext, an ordering, a return value, or a
database write.
"""

import json
import os
import threading
import time

_PATH = os.environ.get('HELIOS_MEASURE_PATH')
_ENABLED = bool(_PATH)

# Instrumentation-only cost accrued in the current thread.
#
# THE INVARIANT THIS ENFORCES: a span must never report work that exists only
# because instrumentation is enabled. The only such cost is writing a record
# (~0.06 ms), which happens INSIDE whatever span encloses it, so without
# correction every parent is inflated by its children.
#
# Enforcing it by review failed twice: one instance was found and fixed, then
# another appeared in a place the first audit had not looked. So it is enforced
# structurally instead. Each span notes the accumulator on entry and subtracts
# the delta on exit, and every future addition is handled automatically.
#
# Thread-local because the Celery worker and the Django request each run their
# spans in one thread; nothing here nests across threads.
_local = threading.local()


def _charge(ns):
    """Attribute `ns` of instrumentation-only cost to every enclosing span."""
    _local.overhead = getattr(_local, 'overhead', 0) + ns


def enabled():
    """True when instrumentation is active. For diagnostics only."""
    return _ENABLED


def record(election_uuid, metric, value_ns, **extra):
    """Append one measurement. Never raises: instrumentation must not be
    able to fail an election."""
    if not _ENABLED:
        return
    _t0 = time.perf_counter_ns()
    try:
        row = {
            'election_uuid': str(election_uuid),
            'metric': metric,
            'value': value_ns,
            'unit': 'ns',
            'pid': os.getpid(),
            'wall': time.time(),
        }
        row.update(extra)
        line = json.dumps(row, separators=(',', ':'))
        # One open-append-close per record, O_APPEND. Records are far under
        # PIPE_BUF, so concurrent writes from web and worker processes do not
        # interleave. Volume is a few records per election -- not a hot path.
        #
        # fsync before returning, so a record is on disk before the database
        # field the harness polls is written. The harness therefore never sees
        # a completion signal whose timing is not yet readable.
        with open(_PATH, 'a') as f:
            f.write(line + '\n')
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        pass
    # Writing this record is instrumentation-only work. Charge it so any
    # enclosing span does not report it as Helios's.
    _charge(time.perf_counter_ns() - _t0)


class span:
    """
    with measure.span(uuid, 'aggregation_time_ns'): ...

    Reports the window MINUS any instrumentation-only cost incurred inside it,
    so a span never charges Helios for measurement. `instrumentation_ns` is
    recorded alongside, so the raw window is always recoverable.
    """

    def __init__(self, election_uuid, metric, **extra):
        self.uuid, self.metric, self.extra = election_uuid, metric, extra

    def __enter__(self):
        self._ovh0 = getattr(_local, 'overhead', 0)
        self.t0 = time.perf_counter_ns()
        return self

    def __exit__(self, *exc):
        raw = time.perf_counter_ns() - self.t0
        if exc[0] is None:
            inner = getattr(_local, 'overhead', 0) - self._ovh0
            record(self.uuid, self.metric, max(raw - inner, 0),
                   instrumentation_ns=inner, **self.extra)
        return False
