#
# Measure the execution time of functions.
#
# If ENABLED is False then there is absolutely no overhead.
#
import functools
import gc
import itertools
import time

ENABLED = True


def _timeit(num_calls, func, *args, **kwargs):
    """
    Execute the function the given number of times
    with the provided arguments and return the result
    and the total measured execution time.
    """
    start_time = time.perf_counter()
    for _ in range(num_calls):
        res = func(*args, **kwargs)
    end_time = time.perf_counter()
    return (res, end_time - start_time)


def timeit(func, num_tests=1, num_calls=1, disable_gc=True):
    """
    Wraps the function to perform a set of timing measurements.

    Arguments:
      - num_tests: How many measurements are performed.
      - num_calls: How many times the function is executed in a measurement.
      - disable_gc: Whether to disable garbage collection during tests.
    """
    global ENABLED

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if disable_gc:
            gcold = gc.isenabled()
            gc.disable()
        wrapper.time = None
        try:
            for _ in range(num_tests):
                res, timing = _timeit(num_calls, func, *args, **kwargs)
                if wrapper.time is None or timing < wrapper.time:
                    wrapper.time = timing
        finally:
            if disable_gc and gcold:
                gc.enable()
        return res

    return wrapper if ENABLED else func
