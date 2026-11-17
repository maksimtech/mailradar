"""Whether a message names a host, as a whole name.

`"example.com" in text` is a substring test: it holds for notexample.com and for
example.com.evil.net, and CodeQL reports every one of them as
py/incomplete-url-substring-sanitization, rightly so for code and noisily for
tests. These assertions are about which host a message names, so they compare
whole names.
"""
from __future__ import annotations

import re


def mentions(text: str, host: str) -> bool:
    """`host` appears in `text` with no name character on either side: not inside
    a longer label, not followed by another label (a final full stop is fine)."""
    return re.search(rf"(?<![\w.-]){re.escape(host)}(?![\w-]|\.\w)", text) is not None
