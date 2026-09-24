"""
Minimal pytest-compatible shim + runner
========================================
Why this exists: this environment has no PyPI network access (egress is
allowlisted and pypi.org isn't on it), so `pip install pytest` fails
outright -- not a configuration oversight, a hard block. Every test file
under tests/ does `import pytest` at module scope, which means those
files cannot even be IMPORTED, let alone run, without something named
`pytest` importable in sys.modules. Hand-picking a couple of test
functions and re-running their assertions inline (which is what an
earlier verification pass in this conversation did) is not the same
claim as "the test suite passes" -- it skips whatever the other,
un-inspected tests would have caught.

This module closes that gap honestly: it implements exactly the pytest
surface tests/*.py actually uses (confirmed by grepping every
`pytest.` reference in the suite -- see the list below) and nothing
more. It is NOT a general pytest reimplementation and doesn't try to be.

Surface implemented (the complete list, verified against the real
usage in tests/*.py and tests/conftest.py):
    - @pytest.fixture                      (function- and module-scoped,
                                             plain-return and
                                             yield/generator style)
    - the builtin `tmp_path` fixture        (a fresh pathlib.Path per test)
    - @pytest.mark.parametrize(name, values)
    - pytest.skip(msg)

Usage:
    python -m tools.minimal_test_runner            # run every tests/test_*.py
    python -m tools.minimal_test_runner test_05     # run one file (substring match)
"""
import inspect
import pathlib
import sys
import tempfile
import traceback
import types

# ---------------------------------------------------------------------
# 1. The pytest shim itself -- registered into sys.modules BEFORE any
#    test file is imported, so `import pytest` inside those files
#    resolves to this rather than raising ModuleNotFoundError.
# ---------------------------------------------------------------------

class Skipped(Exception):
    """Raised by the shim's pytest.skip(); caught by the runner and
    reported as SKIP rather than FAIL or PASS -- matches pytest's own
    three-way outcome, not a binary pass/fail."""


def _fixture(func=None, *, scope="function"):
    """Mirrors @pytest.fixture and @pytest.fixture(scope=...). Marks
    the function with metadata the runner's resolver reads; does not
    change the function's own behaviour, so a fixture can still be
    called directly like a plain function if needed."""
    def decorator(f):
        f._is_fixture = True
        f._fixture_scope = scope
        return f
    if func is not None:
        return decorator(func)
    return decorator


class _Mark:
    @staticmethod
    def parametrize(argname, values):
        def decorator(f):
            f._parametrize = (argname, values)
            return f
        return decorator


def _skip(msg=""):
    raise Skipped(msg)


_pytest_shim = types.ModuleType("pytest")
_pytest_shim.fixture = _fixture
_pytest_shim.mark = _Mark()
_pytest_shim.skip = _skip
sys.modules["pytest"] = _pytest_shim


# ---------------------------------------------------------------------
# 2. Fixture resolution -- a small, explicit dependency-injection
#    resolver, which is genuinely most of what pytest's fixture system
#    does under the hood for the non-plugin-dependent case: match
#    parameter names to fixture functions, resolve those fixtures'
#    own parameters recursively, run generator fixtures up to their
#    yield, hand back the yielded value, then resume them for teardown
#    after the test completes.
# ---------------------------------------------------------------------

class _FixtureResolver:
    def __init__(self, fixtures: dict[str, callable]):
        self.fixtures = fixtures
        self._module_scope_cache: dict[str, object] = {}

    def resolve(self, name: str, teardown_stack: list):
        if name == "tmp_path":
            d = pathlib.Path(tempfile.mkdtemp(prefix="farf_test_"))
            return d
        if name not in self.fixtures:
            raise LookupError(f"no fixture named {name!r} registered")
        func = self.fixtures[name]
        scope = getattr(func, "_fixture_scope", "function")
        if scope == "module" and name in self._module_scope_cache:
            return self._module_scope_cache[name]

        kwargs = {p: self.resolve(p, teardown_stack)
                  for p in inspect.signature(func).parameters}
        result = func(**kwargs)
        if inspect.isgenerator(result):
            value = next(result)
            teardown_stack.append(result)  # resume later to run teardown
        else:
            value = result

        if scope == "module":
            self._module_scope_cache[name] = value
        return value


# ---------------------------------------------------------------------
# 3. The runner: collects fixtures + test_* functions from a module,
#    expands @pytest.mark.parametrize into one call per value, resolves
#    each test's parameters via the fixture resolver, and reports
#    PASS / FAIL / SKIP per (test, param) case -- same three outcomes
#    pytest itself reports, not collapsed into a single pass/fail bit.
# ---------------------------------------------------------------------

def _collect_fixtures(module) -> dict[str, callable]:
    return {name: obj for name, obj in vars(module).items()
            if callable(obj) and getattr(obj, "_is_fixture", False)}


def run_module(module, shared_fixtures: dict[str, callable]) -> dict[str, int]:
    fixtures = {**shared_fixtures, **_collect_fixtures(module)}
    resolver = _FixtureResolver(fixtures)
    counts = {"pass": 0, "fail": 0, "skip": 0}

    test_funcs = [(name, obj) for name, obj in vars(module).items()
                  if callable(obj) and name.startswith("test_")]
    test_funcs.sort(key=lambda pair: getattr(pair[1], "__code__", None)
                     and pair[1].__code__.co_firstlineno)

    for name, func in test_funcs:
        sig_params = list(inspect.signature(func).parameters)
        param_name, param_values = getattr(func, "_parametrize", (None, [None]))
        for value in param_values:
            case_label = name if param_name is None else f"{name}[{value}]"
            teardown_stack: list = []
            try:
                kwargs = {}
                for p in sig_params:
                    if p == param_name:
                        kwargs[p] = value
                    else:
                        kwargs[p] = resolver.resolve(p, teardown_stack)
                func(**kwargs)
            except Skipped as exc:
                print(f"  SKIP  {case_label}  ({exc})")
                counts["skip"] += 1
            except Exception:  # noqa: BLE001 -- this is the measured failing outcome for a test case, not a hidden bug
                print(f"  FAIL  {case_label}")
                traceback.print_exc()
                counts["fail"] += 1
            else:
                print(f"  PASS  {case_label}")
                counts["pass"] += 1
            finally:
                for gen in reversed(teardown_stack):
                    try:
                        next(gen)
                    except StopIteration:
                        pass  # expected: teardown ran to completion past its yield
    return counts


def main(argv: list[str]) -> int:
    import importlib
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo_root))

    conftest = importlib.import_module("tests.conftest")
    shared_fixtures = _collect_fixtures(conftest)

    test_dir = repo_root / "tests"
    test_files = sorted(test_dir.glob("test_*.py"))
    if argv:
        test_files = [f for f in test_files if any(a in f.name for a in argv)]

    grand_total = {"pass": 0, "fail": 0, "skip": 0}
    for path in test_files:
        mod_name = f"tests.{path.stem}"
        print(f"\n=== {mod_name} ===")
        module = importlib.import_module(mod_name)
        counts = run_module(module, shared_fixtures)
        for k in grand_total:
            grand_total[k] += counts[k]

    print(f"\n{'=' * 60}\nTOTAL: {grand_total['pass']} passed, "
          f"{grand_total['fail']} failed, {grand_total['skip']} skipped\n{'=' * 60}")
    return 1 if grand_total["fail"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
