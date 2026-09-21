# Backlog

Stato al 2026-09-21.

> Le voci qui sotto sono quelle verificabili dal repository e dal lavoro sul
> lookup DMARC gerarchico (PR #17). Le discussioni precedenti non sono
> accessibili da questa sessione: le sezioni vanno integrate a mano con quanto
> deciso altrove.

## In corso

- **Release 2026.09.11** — bump di `mailradar/__init__.py` (2026.09.10 →
  2026.09.11) e sezione `[Unreleased]` del CHANGELOG chiusa come
  `[2026.09.11] - 2026-09-21`. Il commit è pronto e firmato; manca il suo
  arrivo su `main` (branch protetto) e il tag firmato `v2026.09.11`, che è
  ciò che innesca PyPI (`publish.yml`), Docker (`docker.yml`) e la GitHub
  Release (`release.yml`) — tutti e tre partono su `push` di un tag `v*`.

## Da fare (priorità alta)

- **Public Suffix List reale per il dominio organizzativo.**
  `_MULTI_LABEL_PUBLIC_SUFFIXES` in `mailradar/checker.py` è un sottoinsieme
  statico della PSL. Nella PSL vera `fvg.it` è *essa stessa* un suffisso
  pubblico, quindi il dominio organizzativo di `asufc.sanita.fvg.it` è
  `sanita.fvg.it` e la catena di ricerca attuale scende un livello più del
  dovuto (`fvg.it`). Nessun record DMARC esiste lì, quindi oggi non cambia il
  risultato, ma è una query di troppo e una policy pubblicata su un suffisso
  pubblico verrebbe attribuita al dominio. Valutare `publicsuffixlist` o
  `tldextract` come dipendenza, oppure un aggiornamento periodico della lista.
- **Manutenzione della lista embedded.** Oggi nulla segnala che sia diventata
  obsoleta: serve un criterio di aggiornamento (e un test che lo verifichi).

## Da fare (priorità normale)

- **`reporter.py` ignora l'ereditarietà DMARC.** `DMARCResult` espone
  `found_at`, `inherited` e `sp`, e la CLI mostra `via <dominio padre>`, ma il
  report e-mail non dice che la policy arriva da un dominio padre: chi riceve
  il report non distingue "policy propria" da "policy del padre".
- **Nessun lint in CI.** Nessun workflow esegue `ruff`, benché sia tra le
  dipendenze `dev`. Sul codice attuale segnala: import non usati
  (`mailradar/cli.py` → `domain_exists`, `mailradar/sender.py` → `Path`, più
  alcuni nei test), 2 `F541` in `cli.py`, 1 `E402` in `tests/test_checker.py`.
  Decidere se aggiungere un job di lint e ripulire.
- **Soglia CodSpeed.** La regressione di -11.08% su `test_bench_dmarc` è stata
  riconosciuta, non eliminata: è ~1 µs per lookup, il costo intrinseco di
  normalizzare il dominio e costruire la catena di risalita (irrilevante
  accanto ai 10–50 ms di una query DNS reale, ma sopra la soglia di CodSpeed,
  che misura con il resolver mockato). Decidere se alzare la soglia o
  riconoscere le regressioni caso per caso.
- **Baseline CodSpeed su runtime diverso.** CodSpeed ha segnalato *"Different
  runtime environments detected"* confrontando `BASE` e `HEAD`: i confronti di
  performance sono meno affidabili finché la baseline non viene rimisurata
  sullo stesso runner.

## Backlog feature

- *Nessuna voce verificabile da questa sessione.* Da integrare con le idee
  discusse altrove.
- Proposte nate dal lavoro sul lookup DMARC, da confermare:
  - opzione per disattivare la risalita e verificare solo l'hostname esatto,
    utile in audit stretti su un singolo host;
  - esporre nel report e-mail il dominio di provenienza della policy e il tag
    `sp=` (si sovrappone alla voce su `reporter.py`).

## PR in attesa maintainer

- **#16** — `chore(deps): bump idna from 3.19 to 3.20` (Dependabot), aperta il
  2026-09-21, base `main`, nessuna review: in attesa di merge o di una
  decisione.
- **#17** — `fix(dmarc): RFC 7489 organizational domain lookup`: mergiata il
  2026-09-21. Nessuna azione, resta qui come riferimento della release in
  corso.
