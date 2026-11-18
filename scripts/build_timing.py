"""Thread-safe aggregate timings for build profiling (durations overlap across workers)."""
import atexit
from collections import defaultdict
from functools import wraps
from threading import Lock
from time import perf_counter

_totals = defaultdict(lambda: [0, 0.0])
_lock = Lock()
_started = perf_counter()


def timed(name):
    def decorate(function):
        @wraps(function)
        def measured(*args, **kwargs):
            started = perf_counter()
            try:
                return function(*args, **kwargs)
            finally:
                with _lock:
                    totals = _totals[name]
                    totals[0] += 1
                    totals[1] += perf_counter() - started
        return measured
    return decorate


def report():
    print(f"PROFILE process wall: {perf_counter() - _started:.2f}s", flush=True)
    for name, (calls, seconds) in sorted(_totals.items()):
        print(f"PROFILE {name}: {calls} calls, {seconds:.2f}s cumulative", flush=True)


atexit.register(report)
