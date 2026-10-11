# MailRadar — CLAUDE.md

Contesto rapido per riprendere il lavoro senza ricostruire la storia.

## Cos'è

Analizzatore di email security posture: DMARC, SPF, DKIM, BIMI, VMC e GPG.
Scopre i domini da un file di input, li audita, genera un report HTML in
italiano o inglese. CLI Typer, nessuna API/DB (tool da riga di comando puro).

Repo: <https://github.com/maksimtech/mailradar>

## Struttura

```
mailradar/
  cli.py         # entry point `mailradar`
  discover.py    # trova domini dalla lista input
  checker.py     # audita DMARC/SPF/DKIM/BIMI/VMC
  sender.py      # invia il report via email
  reporter.py    # genera HTML dal template Jinja2
  gpg.py         # verifica GPG dei report
  law_fetcher.py # scarica GDPR/NIS2 da Cellar/EUR-Lex (copia da patchradar)
  law_checker.py # confronta testo con cache SHA-256
  law_cache.py   # ~/.mailradar/law_cache.json
  templates/
    report_it.j2
    report_en.j2
  public_suffix_list.dat
tests/           # pytest (NO asyncio — mailradar è tutto sync)
```

## Comandi essenziali

```bash
pip install -e . --break-system-packages

# Test (niente asyncio_mode nel pytest.ini — non usare pytest-asyncio qui)
python -m pytest tests/ -q
python -m pytest tests/test_law_fetcher.py -q

# Coverage law_fetcher
python -m pytest tests/test_law_fetcher.py \
  --cov=mailradar.law_fetcher --cov-report=term-missing -q

ruff check mailradar/ tests/
mypy mailradar/
```

## Differenze rispetto a patchradar

| Aspetto | mailradar | patchradar |
|---------|-----------|------------|
| asyncio | No | Sì (`asyncio_mode = "auto"`) |
| DB | No | aiosqlite |
| API | No | FastAPI |
| `_client()` nei test | con `follow_redirects=True` | senza (gestisce redirect a mano) |
| Cache home | `~/.mailradar/` | `~/.patchradar/` |

**Attenzione:** `law_fetcher.py` in mailradar usa `_get()` con
`follow_redirects=True` (httpx segue i redirect automaticamente). In
patchradar usa `_get_over_https()` con `follow_redirects=False` e gestione
manuale. Le due implementazioni si assomigliano ma non sono identiche —
non copiare test da un repo all'altro senza verificare.

## law_fetcher.py — stato

- Fix HTTPS redirect Cellar (`e7974de`) mergato su main
- Test ephemeral-client e https-upgrade failure paths (`95b4070`) su main
- Stesse sorgenti di patchradar: Cellar prima, EUR-Lex fallback

## Git

Branch principale: `main`. Push diretto per fix/test.  
Prefissi commit: `fix(scope):`, `test(scope):`, `feat(scope):`, `docs(scope):`.

Attribuzione da aggiungere in fondo a ogni commit:
```
Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0154qVT8TUGnkx4DFoZCbD76
```

## PR recenti

- `#42` — fix HTTPS redirect Cellar (mergata, stessa fix di exeradar)
- `#41` — chiusa come superseded da #42
- `#30` — fix 24 difetti da code review

## Note veloci

- Nessun `asyncio_mode` nel pyproject: i test sono tutti sincroni
- `public_suffix_list.dat` bundled nel pacchetto (non scaricato a runtime)
- `~/.mailradar/law_cache.json` — stesso schema di patchradar/exeradar
