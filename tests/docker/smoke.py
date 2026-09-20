"""
Docker smoke test: the installed CLI must be importable and report the version
the image was built for. Mirrors cookieradar's tests/docker/smoke.py.
"""
import os
from importlib.metadata import version

NAME = "mailradar"


def _normalize(v: str) -> str:
    # PEP 440 drops leading zeros: 2026.09.4 -> 2026.9.4
    return ".".join(str(int(p)) if p.isdigit() else p for p in v.lstrip("v").split("."))


expected = os.environ.get("EXPECTED_VERSION")
installed = version(NAME)
if expected:
    assert _normalize(installed) == _normalize(expected), f"installed {installed}, expected {expected}"
print(f"smoke: mailradar {installed} OK")
