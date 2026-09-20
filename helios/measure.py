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
import time

_PATH = os.environ.get('HELIOS_MEASURE_PATH')
_ENABLED = bool(_PATH)


def enabled():
    """True when instrumentation is active. For diagnostics only."""
    return _ENABLED


def record(election_uuid, metric, value_ns, **extra):
    """Append one measurement. Never raises: instrumentation must not be
    able to fail an election."""
    if not _ENABLED:
        return
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


class span:
    """with measure.span(uuid, 'aggregation_time_ns'): ..."""

    def __init__(self, election_uuid, metric, **extra):
        self.uuid, self.metric, self.extra = election_uuid, metric, extra

    def __enter__(self):
        self.t0 = time.perf_counter_ns()
        return self

    def __exit__(self, *exc):
        if exc[0] is None:
            record(self.uuid, self.metric,
                   time.perf_counter_ns() - self.t0, **self.extra)
        return False
