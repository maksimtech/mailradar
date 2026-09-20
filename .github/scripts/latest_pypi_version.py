"""Print the latest version of a package on PyPI."""
import json
import sys
import urllib.request

with urllib.request.urlopen(f"https://pypi.org/pypi/{sys.argv[1]}/json", timeout=30) as r:
    print(json.load(r)["info"]["version"])
