# MailRadar — istruzioni per Claude Code

Claude Code legge questo file da solo. Contiene regole di lavoro e fatti che il
repository conferma; la storia sta nel CHANGELOG e nelle pull request, non qui.

## Cos'è

Analizzatore della postura di sicurezza email di un dominio (DMARC, SPF, DKIM,
BIMI, VMC, MTA-STS, TLS-RPT, GPG), a riga di comando. Comandi: `check`, `batch`,
`report`, `send`, `discover`. Cosa contatta in rete e cosa scrive su disco è in
`docs/nis2-compliance.md`, sezione 3.

## Regole di lavoro

- **Ogni modifica passa da una pull request** su `main`, unita quando i controlli
  obbligatori sono verdi. Dal 2026-10-12 il ruleset non ha eccezioni, nemmeno per
  il proprietario: un push diretto su `main` viene rifiutato, e lo è anche
  `gh pr merge --admin`. Anche il commit di versione passa da una PR (vedi
  Release).
- **Commit firmati** con l'identità e la chiave configurate nel repository:
  `git log -1 --format=%G?` deve dare `G`. Messaggi `tipo(ambito): …`, con il
  perché nel corpo. La riga `Co-Authored-By` la indica l'ambiente di Claude Code;
  non scrivere nomi di modello né link a sessioni in questo file.
- **TDD**: il test che riproduce il difetto fallisce prima della correzione, e si
  vede fallire.
- **Niente mock.** Input reali, oggetti reali, server locali veri (in
  `tests/replay.py` ci sono DNS, HTTP e SMTP su 127.0.0.1 con una CA di test). Al
  confine di rete si possono riprodurre solo risposte registrate dal servizio
  vero, in fixture che lo dichiarano (`_recorded`); una fixture costruita o
  ricavata si dichiara `_derived`. Risposte inventate e patch di funzioni interne
  per simulare un comportamento non si usano. "Non misurato" non è zero.
- **`docs/nis2-compliance.md` è documentazione per i clienti** ed è tenuta al
  codice da `tests/test_nis2_evidence.py`: se cambiano gli host contattati, i file
  scritti, l'immagine o i workflow, il documento si aggiorna nella stessa PR.
  Nessuna affermazione che il repository non possa dimostrare.
- **Avvisi di sicurezza accettati** solo in `SECURITY-EXCEPTIONS.toml`, con motivo
  e `review_by`; mai `# nosec` o `# noqa` per zittire uno scanner.
- **Repository di terzi**: nessuna issue, PR o commento senza conferma esplicita
  del proprietario.

## Comandi

Come li esegue la CI (Quality e Tests). Su Windows il Python del venv è
`.venv/Scripts/python`, su Linux `.venv/bin/python`.

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"
.venv/Scripts/python -m pytest -q
.venv/Scripts/ruff check mailradar tests tools
.venv/Scripts/mypy mailradar
uv lock --check            # con uv 0.12.18, la versione fissata in quality.yml
```

Su Windows i test di `tests/test_release_script.py` falliscono anche su un `main`
pulito, perché lanciano bash: non sono regressioni. Per confrontare, usare un
`git worktree add --detach <cartella> origin/main`.

## Release

`./release.sh X` (CalVer `YYYY.count[.fix]`) controlla, porta la versione, fa
girare la suite e mette il commit di versione su `release/vX`, poi pubblica solo
quel ramo. Se `gh` c'è e `origin` è questo repository su GitHub, apre la PR con
auto-merge, aspetta che GitHub la unisca (al massimo `RELEASE_WAIT_MINUTES`,
default 60) e crea il tag `vX` sul commit di `main`. `./release.sh --tag X` fa solo
quest'ultimo passo, se l'attesa si è interrotta. Il tag fa partire PyPI, la
release GitHub con le note dal CHANGELOG e l'immagine `maksimtech/mailradar:vX`;
poi Release Evidence (`sbom.yml`) allega SBOM e scansioni datate. Per una release
già uscita: `gh workflow run sbom.yml -f tag=vX`.

## Note

- `law_fetcher.py` e `law_cache.py` sono copiati, non condivisi, in mailradar,
  exeradar, cookieradar, apkradar e patchradar: una correzione va portata in
  tutte le copie. I redirect si seguono a mano e mai in chiaro
  (`_get_over_https`): Cellar risponde con un 303 verso `http://`.
- I test sono sincroni: niente `asyncio_mode` (vedi il commento in
  `pyproject.toml`).
