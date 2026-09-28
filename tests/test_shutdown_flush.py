"""
MailRadar — lo spinner non deve lasciare niente nel buffer di Rich.

Mentre `console.status()` gira, Rich sostituisce `sys.stdout` e `sys.stderr` con
un `FileProxy` che trattiene il testo finché non incontra un newline, e `Live`
ripristina i flussi originali **senza svuotare quel buffer**. Una riga parziale
scritta da una libreria resta lì e viene stampata quando l'interprete finalizza
l'oggetto, quando importare non è più possibile:

    Exception ignored while finalizing file <rich.file_proxy.FileProxy object …>
    ImportError: sys.meta_path is None, Python is likely shutting down

Un comando riuscito finisce quindi con un traceback. Osservato su APKRadar con
rich 15.0.0 e Python 3.14.7; qui gli spinner avvolgono le query DNS, la lettura
di crt.sh e l'invio delle lettere, cioè codice di terzi che scrive sui flussi.

Il test gira in un sottoprocesso perché la finalizzazione è ciò che si misura, e
dentro il processo di pytest non avverrebbe mai. Serve un `Console` che si crede
un terminale: Rich installa il proxy solo in quel caso, ed è la ragione per cui
in pipe il difetto non si vede.
"""
import subprocess
import sys

_SHUTDOWN_SCRIPT = """
import sys
from unittest.mock import patch

import typer
from rich.console import Console

import mailradar.checker as checker
import mailradar.cli as cli


def fake_domain_exists(domain):
    # Una libreria che tiene un riferimento a sys.stdout mantiene vivo il
    # FileProxy di Rich oltre la fine dello spinner, con la riga parziale dentro.
    global held_stdout
    held_stdout = sys.stdout
    sys.stdout.write("riga-parziale-senza-newline")
    return False


with patch.object(checker, "domain_exists", fake_domain_exists), \\
     patch.object(checker, "find_domain_variants", lambda domain: []), \\
     patch.object(cli, "console", Console(force_terminal=True, width=250)):
    try:
        cli.app(["check", "esempio.invalid"], standalone_mode=False)
    except typer.Exit:
        pass
"""


def test_check_leaves_nothing_in_the_proxy_buffer():
    proc = subprocess.run(
        [sys.executable, "-c", _SHUTDOWN_SCRIPT],
        capture_output=True, text=True, timeout=120,
        encoding="utf-8", errors="replace",
    )

    assert proc.returncode == 0, proc.stderr
    assert "sys.meta_path is None" not in proc.stderr
    assert "Exception ignored" not in proc.stderr
    # E la riga parziale non va persa: svuotare il buffer significa stamparla,
    # non buttarla. Una correzione che la scartasse passerebbe i due controlli
    # sopra e nasconderebbe l'output di una libreria.
    assert "riga-parziale-senza-newline" in proc.stdout
