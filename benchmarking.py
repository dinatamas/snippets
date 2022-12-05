"""
The timeit decorator can be used to measure the execution time of functions.
It uses the same timing methods as the timeit standard library module.

By default timing measurements are disabled and there is no runtime overhead
by having the decorators present in your code. To enable bechmarking, set the
ENABLE_BENCHMARKING environment variable.

An added benefit compared to the timeit module is that the function that the
timeit decorator returns mimics the original function, i.e. it can fit into
the normal program flow perfectly. If the return value changes during
repeated calls or if the function has some side effects, only run one test
and one function call at a time. This gives less reliable results, but you
can still execute your main program multiple times to repeat the measurement.

The measurements are recorded in /tmp/benchmarking.log for later analysis.
"""
from datetime import datetime
import functools
import gc
import inspect
import logging
import os
import time
from typing import Any, Callable

ENABLED = bool(os.getenv('ENABLE_BENCHMARKING', False))

_logger = logging.getLogger('benchmarking')
_logger.setLevel(logging.INFO)
_formatter = logging.Formatter('%(asctime)s.%(msecs)06d -- %(message)s', '%Y-%m-%d %H:%M:%S')
_file_handler = logging.FileHandler('/tmp/benchmarking.log')
_file_handler.setLevel(logging.INFO)
_file_handler.setFormatter(_formatter)
_logger.addHandler(_file_handler)
if ENABLED:
    _logger.info(f'Benchmarking module loaded at {datetime.now()}')


def _timeit(func: Callable, num_calls: int, *args, **kwargs) -> (Any, float):
    """
    Execute the function the given number of times with the provided arguments,
    and return the (last) result along with the total measured execution time.
    """
    start_time = time.perf_counter()
    for _ in range(num_calls):
        res = func(*args, **kwargs)
    end_time = time.perf_counter()
    return (res, end_time - start_time)


def timeit(
    func: Callable,
    num_tests: int = 1,
    num_calls: int = 1,
    disable_gc: bool = True
) -> Callable:
    """
    Wraps the function to perform a set of timing measurements.

    Arguments:
      - num_tests: How many measurements are performed.
      - num_calls: How many times the function is executed in a measurement.
      - disable_gc: Whether to disable garbage collection during tests.
    """
    if not ENABLED or num_tests == 0 or num_calls == 0:
        return func

    funcinfo = (
        f'{func.__name__} from ({func.__module__}'
        f':{inspect.getsourcelines(func)[1]})'
    )

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if disable_gc:
            gcold = gc.isenabled()
            gc.disable()
        best_measurement = float('inf')
        try:
            for _ in range(num_tests):
                res, measurement = _timeit(func, num_calls, *args, **kwargs)
                best_measurement = min(best_measurement, measurement)
            _logger.info(
                f'{funcinfo} executed {num_calls} times in under '
                f'{best_measurement:.6f}s in {num_tests} tests'
            )
            return res
        finally:
            if disable_gc and gcold:
                gc.enable()

    return wrapper
