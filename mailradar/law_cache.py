"""
MailRadar — local cache of EU law provisions.

Stored in ~/.mailradar/law_cache.json (or $MAILRADAR_HOME/law_cache.json):

    {
      "checked_at": "2026-10-01T09:30:00Z",
      "entries": [
        {"article": "32(1)(a)", "text": "...", "sha256": "...",
         "fetched_at": "2026-09-19T14:00:00Z", "celex": "32016R0679"}
      ]
    }

An entry keeps the fetched_at of the first download of its wording: an audit
that finds the same text on EUR-Lex only updates checked_at, so the version
date in reports changes only when the law text does. Entries are keyed by
(celex, article), since article numbers repeat across acts.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from mailradar.law_fetcher import Provision, text_sha256

Key = tuple[str, str]   # (celex, article)


def default_cache_path() -> Path:
    """Where the cache lives, from MAILRADAR_HOME or the default under $HOME.

    The value is expanded and resolved rather than used as written. Path()
    takes "~/cache" as a directory actually named "~", and a relative value
    against the working directory — so the same setting produced a different
    cache depending on where the command was run from, quietly turning one
    cache into several. Blank or whitespace means "unset", not "a directory
    named space".

    Only the directory is configurable. The filename is fixed here, which is
    what keeps the variable from choosing which file gets written over.
    """
    home = (os.environ.get("MAILRADAR_HOME") or "").strip()
    if not home:
        return Path.home() / ".mailradar" / "law_cache.json"
    base = Path(home).expanduser()
    # A relative value is anchored to $HOME, not to the working
    # directory: otherwise the same setting names a different
    # cache from every directory the command is run in, and one
    # cache quietly becomes several.
    if not base.is_absolute():
        base = Path.home() / base
    return base.resolve() / "law_cache.json"


class LawCache:

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else default_cache_path()

    def load(self) -> dict[Key, Provision]:
        """
        Cached provisions by (celex, article). A missing or unreadable file is
        an empty cache, and an entry whose SHA-256 does not match its text is
        dropped: it cannot be cited as verified.
        """
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        entries = data.get("entries") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            return {}

        provisions = {}
        for entry in entries:
            try:
                provision = Provision.from_dict(entry)
            except (KeyError, TypeError):
                continue
            if provision.sha256 == text_sha256(provision.text):
                provisions[provision.key] = provision
        return provisions

    def update(
        self, fresh: dict[Key, Provision], checked_at: str
    ) -> tuple[dict[Key, Provision], dict[Key, str]]:
        """
        Merge freshly downloaded provisions into the cache and save it.

        Returns:
            (provisions, changed): all cached provisions after the merge, and
            for each provision whose text differs from the cached one, the
            SHA-256 of the previous text.
        """
        provisions = self.load()
        changed = {}
        for key, provision in fresh.items():
            old = provisions.get(key)
            if old is not None and old.sha256 == provision.sha256:
                continue
            if old is not None:
                changed[key] = old.sha256
            provisions[key] = provision
        self._save(provisions, checked_at)
        return provisions, changed

    def _save(self, provisions: dict[Key, Provision], checked_at: str) -> None:
        data = {
            "checked_at": checked_at,
            "entries": [provision.to_dict() for provision in provisions.values()],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Write then rename, so an interrupted audit never leaves half a file
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".law_cache.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
                fh.write("\n")
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
