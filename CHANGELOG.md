# Changelog

All notable changes to MailRadar are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses **CalVer, Apple style**: `YYYY.count[.fix]`, not SemVer.
`YYYY` is the generation, shared by the five Radar; the count belongs to each of
them and moves when its code moves; the third segment is for something urgent on
what has already shipped. The line above described `YYYY.0M.PATCH` until
2026-09-29, which no version in this file has ever matched — 40 is not a month,
and `tests/test_version_contract.py` has been enforcing the real form all along.

## [Unreleased]

### Added

- **The files the build is told to include are checked to be there.** apkradar lost its
  `LICENSE` out of the working tree on 2026-10-04 and the loss reached `main`: pyproject
  names the file, so `python -m build` failed with `License file does not exist: LICENSE`,
  and the PyPI publish and the image went down with it. cookieradar lost its own a few
  hours later, during a run of the suite. Neither suite noticed, because neither looked.

  What removes them is still not known, and these cases do not explain it. They stop it
  reaching a commit, which is the part that can be fixed without knowing.

  The expectation is read out of the declarations rather than written down as `LICENSE`,
  because the five Radar do not declare it the same way: patchradar states its licence as
  text and only its Dockerfile names the file, the other four name it in pyproject, and of
  those apkradar and mailradar do not copy it into the image. So two cases — every file
  pyproject names, and every path the Dockerfile copies — and between them each repository
  is covered, three of them twice.

  Checked by moving the file aside in all five: it fails where it should and passes where
  the declaration genuinely does not name it, and pointing pyproject at a file that is not
  there fails too.

### Fixed

- **The OCI licence label is the key the standard names.** It read
  `org.opencontainers.image.license`, singular, which nothing reads — so a tool asking the
  image what it is licensed under got no answer, while the label looked right in the file.

- **Two defences in `release.sh` that the tests did not actually measure.** Found by
  mutating the script rather than by reading it.

  Replacing the existing-tag check's `fail` with an `echo` of the same words left every
  case green: the script carried on, bumped, **committed**, and only then did `git tag`
  refuse the tag that already existed. The release was still refused — one commit too
  late, which is the opposite of what the script promises, that a refusal leaves the
  version file modified and nothing else. The cases now check that it did not commit on
  its way to refusing.

  And `git push --atomic` was not measured at all; two separate pushes passed. With two
  pushes `main` arrives and the tag does not, so the repository carries a version bump
  that no release and no published artifact corresponds to — and the tag that would
  produce them cannot be pushed afterwards either, because the version it would be
  given is by then "already the current version". A `pre-receive` hook on the test
  remote now refuses tags, which is the way to make the second half fail on demand.

  Both mutations fail now, along with the three that already did.

- **The PyPI wait allows a margin once the index answers.** apkradar's Docker build
  failed on 2026-10-03 with `No matching distribution found` **fifteen seconds after**
  the wait had reported the version available — 16:31:21 against 16:31:36. The poll is
  not wrong and not enough: it establishes that the file is reachable from the runner,
  while the build container, multi-platform through buildx, resolves the index again
  and can reach an edge still serving the old one.

  This is not the `sleep 60` that stood in that step before polling and lost the race
  twice. That was a guess about how long publishing takes, made before knowing
  anything; this waits for the fact first and then allows a bounded margin for it to
  propagate, and says so in the log when it uses one.

  It narrows the window; it does not close it. What closes it is not asking the index
  during the build at all — which is what exeradar's Dockerfile already does, with
  `pip install /app/src`, and why exeradar has no wait script and did not hit this.
  cookieradar and patchradar are one word from that (`_SOURCE=local`); apkradar and
  mailradar would need the build argument added. That is the follow-up.

  Three cases hold the margin, and they were needed twice over. The two cases that
  already drove this script pass the retry interval as zero so they stay fast, and the
  new default made every success wait 45 seconds past their timeout — so the suite was
  red in all four repositories until those two were told to ask for no grace. Telling
  them that alone would have left the margin itself unmeasured, which is the shape of
  defect this script was written to fix in the first place. So: one case times a
  two-second grace and checks the log says why it waited, one checks that no grace
  waits for nothing and claims nothing, and one measures the *default* without the
  suite paying 45 seconds for it — started with no grace argument, the script must
  still be running three seconds after the index answered. All four ways of undoing
  the margin were checked against them: the default set to zero, the wait removed
  while the log still claims it, the log removed while the wait still happens, and the
  guard removed so zero waits anyway.

- **`send` verifies the SMTP server's certificate.** `SMTP_SSL` and `starttls()` were
  called without a context, and smtplib then verifies neither the certificate nor the
  host name: anyone on the path could present any certificate and receive the SMTP
  password given to `login()`. Both now use `ssl.create_default_context()`, and the
  connection gives up after 30 seconds instead of waiting for ever.

- **SPF is read term by term, as RFC 7208 defines it, not searched for substrings.**
  `v=spf1 mx all` — `all` with no qualifier, which is `+all` and lets every server pass —
  scored like a correct record and showed ✅. `include:spf-all.example.net ~all` was read
  as `-all`, `-ALL` as no `all` at all, and `+all` raised the `+a or +mx` warning. Also
  now: a record without `all` follows its `redirect=` (gmail.com's form), and with
  neither it is reported as neutral; two SPF records, a `redirect=` to a name with none,
  and more than 10 DNS lookups once `include:` and `redirect=` are followed (an include
  loop included) are a permerror, scored 0 and never shown as ✅. `SPFResult` gains
  `permerror`, and the law check counts it as weak SPF.

- **DMARC: values are case-insensitive, and two records are no policy.** `p=REJECT;
  adkim=S` was scored as `p=none` and the report told the owner no protection was
  active. Two records on `_dmarc.<domain>` end policy discovery (RFC 7489 §6.6.3); the
  first one was used instead. `v = DMARC1` is a valid record, and an empty `rua=` or
  `ruf=` no longer counts as reports configured.

- **A DNS lookup that fails is no longer reported as a missing record.** A resolver
  timeout or SERVFAIL was read as "no record", so the report sent to the owner could say
  "No DMARC record found — domain is spoofable" about a domain nobody had managed to ask.
  The check is now marked not verified (`error` on each result): no claim either way, a
  ⚠️ in the table, nothing for the law check to cite, and `report` and `send` refuse to
  produce a report from an incomplete analysis. A DKIM selector that fails no longer
  hides the next one.

- **DKIM: Ed25519 keys are strong and an empty `p=` is a revoked key.** A `k=ed25519` key
  (RFC 8463, 32 raw bytes) failed to parse as DER and was scored as weak 512-bit RSA, and
  the law check cited GDPR over it. An empty `p=` revokes the key (RFC 6376 §3.6.1): it
  was shown as "512-bit RSA" too — the `example.com` output in the README was exactly
  that. The next selector is now tried, and the revocation is reported if no active key
  is found.

- **BIMI downloads the logo only from a public `https://` URL.** `l=` comes from the
  analysed domain's DNS, that is from a third party, and any URL in it was fetched:
  `l=http://127.0.0.1:8080/admin` reached the network MailRadar runs on. Plain http and
  IP literals that are not global are now refused; a host name is still not checked for
  what it resolves to. `v=BIMI1; l=; a=;` declines BIMI and no longer earns 3 points.

- **The organizational domain comes from the Public Suffix List.** The embedded subset of
  two-label suffixes lacked `co.at` and hundreds more, so `_dmarc.co.at` was queried as
  the parent of `example.co.at` — against the README's promise that the public suffix is
  never queried. The full list now ships with the package (`public_suffix_list.dat`, no
  new dependency, read offline). It is Mozilla's and stays under MPL-2.0: the file keeps
  its licence header, the README's License section credits it, and the comment where it
  is loaded says how to refresh it. This changes one documented case: `fvg.it` is on the list,
  so for `asufc.sanita.fvg.it` the walk stops at `sanita.fvg.it` and no longer asks
  `_dmarc.fvg.it`. In DNS that is where the record actually is: on 2026-10-07
  `_dmarc.sanita.fvg.it` answered and `_dmarc.fvg.it` was NXDOMAIN.

- **MTA-STS: what the report says matches what was found.** A policy file answering 404
  raised no issue at all, and the report for the owner said "Current: Not configured" for
  a policy in testing mode.

- **Smaller fixes.** `check example.com.` treated the trailing dot as a missing domain,
  and `analyze_domain` now normalises the name once, so GPG and MTA-STS no longer see
  `Example.COM.`. RDAP addresses are matched on the domain, not as a substring
  (`admin@example.com.evil.org`). `python -m mailradar.cli` ran the app before `report`,
  `send` and `discover` were defined. `batch` crashed with a Rich `MarkupError` on a file
  name containing `[`.

### Changed

- **The race with PyPI is closed rather than narrowed: the released image no longer asks
  the index.** `docker.yml` installed `mailradar==<the new version>` from PyPI and polled
  the index first to make that work. The poll runs on the runner; the multi-platform build
  resolves the index again, per platform, from whichever edge answers. apkradar lost that
  race on 2026-10-03 **fifteen seconds after** its poll had succeeded; this repository
  passed on timing alone, which is not the same as being safe. Nothing that waits can close
  it. Not asking does, so the image is built from the source the tag points at.

  The Dockerfile could not do that — it only knew how to install from the index — so it
  gained the `local`/`pypi` switch the other Radar have, with `local` as the default and the
  source copied in. `ARG MAILRADAR_VERSION=2026.9.2` went with it: that default stood while
  this project was at 2026.42, so `docker build .` rebuilt September and nothing about it
  looked wrong.

  **The build now stands on the tag it resolved, and that is a step rather than a `ref:` on
  the checkout.** The tag arrives in a different place on each of the three triggers: in the
  ref on a tag push, in the input on a dispatch, and nowhere at all on the weekly schedule,
  where the version step finds it with `git tag --list --sort=-v:refname`. A `ref:` cannot
  express the third case, because the tag is not known until the tags have been fetched.

  It matters most on the schedule. `latest` is rebuilt weekly to pick up Debian's patches,
  and built from the checkout without this it would be rebuilt from whatever `main` holds —
  which is how `latest` ends up carrying unreleased code under a released version's name.
  Nothing between the build and the push would catch it: unlike exeradar and cookieradar,
  this workflow has no smoke test there.

  Wheels are still asked for first on both branches, and both still retry without
  `--only-binary :all:` if that fails. The retry is older than this change and was kept as
  it was: why it is needed is not recorded, and removing it would make this build stricter
  than it has ever been for a reason that cannot be checked without a Docker daemon. The new
  case says *asked for*, which is what is true, rather than claiming a guarantee.

  The image is built on every push and pull request now. `docker-build-check.yml` could not
  run on its own before — the Dockerfile needed a published version handed to it — so the
  only thing that built this image automatically was the workflow that publishes it. Given a
  version it still reproduces that one from the index, which keeps `latest_pypi_version.py`
  in use rather than orphaned.

  And that the file on PyPI can be installed, which the old arrangement proved by accident,
  is now checked on purpose in `publish.yml` after the upload — with no margin, because
  there is a single resolver there.

  Eleven mutations hold all of it, and all eleven fail: the image back on the index, the
  build off the resolved tag, that step no longer given the version, a shallow checkout, the
  published file unchecked, a margin where there is one resolver, the build check no longer
  running on pull requests, the Dockerfile defaulting to `pypi`, a stale version default
  restored, the local branch not asking for wheels, and the licence label back to singular.

- **`release.sh` runs the suite after the bump, and refuses before committing.**
  The version is written as the script's first act, so a suite run *before* a
  release cannot see what the bump breaks. Twice — apkradar 2026.42 on 2026-10-03
  and 2026.43 on 2026-10-04 — `test_the_readme_states_the_version_it_was_captured_with`
  failed in CI, on `main`, with the tag already pushed, and was fixed by hand after
  the fact.

  The gate sits between writing the version and committing it, not after: a refusal
  then leaves the version file modified and nothing else touched, which is what
  somebody needs to see, and `git checkout` undoes it. A gate after the commit would
  have to undo a commit, and undoing is worse than not doing. A repository with no
  `tests/` is not held up by a suite it does not have.

  Three cases hold it, and the first was checked against the script without the gate:
  a failing suite stops the release with nothing committed, tagged or pushed; a
  passing one lets it through; and no `tests/` is not a failure.


## [2026.42] - 2026-10-04

### Added

- **The gate reads FIRST's forecast on the CVEs it already holds.** EPSS is indexed
  by CVE, and `SECURITY-EXCEPTIONS.toml` is the one surface in this repository that
  holds CVE ids: Docker Scout names its alerts by CVE, so every accepted finding
  already has an id, a written reason and a review date. The forecast is what those
  records lacked — "no fix in any suite" accepted until December is comfortable at
  an EPSS of 0.1% and is something else at 40%.

  The forecast changes no verdict. The gate fails on a blocking alert with no entry
  and on an entry past its date, and on nothing else: `exit_code` takes the
  forecasts and ignores them, so the signature says they were available and did not
  decide anything. Only ids that *are* CVE ids are looked up —
  `SNYK-DEBIAN13-GCC14-20386241` is CVE-2026-95619 and says so in its description,
  and reading prose is guessing. A CVE FIRST does not score prints "not scored by
  FIRST" rather than 0.0%, which is a real reading at the floor of the scale; FIRST
  unreachable prints nothing and the report is the one this script produced before.

  The accepted findings are listed on a **passing** run, worst first, because that
  is where somebody decides whether to renew a review date and nothing else prompts
  it.

  Ported from patchradar with its nineteen tests; `tools/security_exceptions.py` is
  shared by copy across the five, and all four copies were byte-identical before
  this.

### Fixed

- **Mutation testing runs again: `also_copy` in `[tool.mutmut]`.** The Saturday
  run died in all five Radar on 2026-10-03, before a single mutant was tried, and
  the cause was the same one each time with a different victim — here, `tests/test_docker.py` could not read `Dockerfile`.

  mutmut copies `source_paths` into `mutants/` and runs the suite from there,
  adding only `tests/`, `test/`, `setup.cfg`, `pyproject.toml` and `uv.lock` of its
  own accord. So every test that imports from `tools/` or `scripts/`, or reads a
  file at the repository root, found nothing — and since the stats phase runs the
  suite rather than merely collecting it, one such test killed the whole run.

  The list was verified rather than guessed. mutmut 3.8 refuses to run on Windows,
  so the `mutants/` tree was rebuilt by hand from mutmut's own copy rules —
  `configuration.py:184` and `utils/file_utils.py:66` — and the suite run inside it
  until it passed: **435 passed, 4 skipped**.

  This is *not* the previous day's move to `ubuntu-26.04`: the failures are
  Python-level, inside a copied tree, and patchradar's instance dates from
  2026-09-26. The weekly cron is only what surfaced them all at once — the first
  firing since the tests that trip it were written.

- **The image Snyk scans has a fixed tag, so code scanning keeps one
  configuration for it.** It was built as `snyk-scan:${GITHUB_SHA}`, and Snyk
  Container writes its own automation id into the SARIF from the image reference it
  scanned — overriding the `category:` given to `upload-sarif`. So every commit
  minted a new code-scanning configuration that nothing could ever find again, and a
  pull request was told *"configurations present on refs/heads/main were not
  found"* and could no longer be shown which alerts it had introduced.

  Measured on 2026-10-02 in apkradar, which had reached **32** of them and whose
  pull request #16 could not be diffed. This repository shows one, because its image
  does not carry the extra target Snyk names the image in. The tag is the same in
  all five, so the fix is too: the defect is there whether or not it has surfaced.

- **A test was pinning Rich's output stream for every test that ran after it.**
  `test_the_console_is_flushed_even_when_the_body_raises` saved `cli.console.file`
  and assigned it back, which looks like a restore and is not: Rich's `file` is a
  property that falls back to `sys.stdout` when nothing was set, so writing the
  current value into it fixes that stream for good. Any later test rendering
  through this console then wrote to the terminal instead of to the CliRunner's
  buffer. Measured on apkradar, where the sibling of this test left
  `tests/test_hash_is_verifiable.py` asserting against an empty `result.output`;
  the suite passed only because of the order the files happen to be collected in.
  The test now builds a console of its own and puts it in place of the module's,
  through monkeypatch.

### Changed

- **The CI runners are pinned to `ubuntu-26.04`, and the benchmarks job is pinned
  to `ubuntu-24.04` because CodSpeed cannot run on 26.04.** `ubuntu-latest` was
  Ubuntu 24.04 — read off a live run on 2026-10-02, image `ubuntu24/20260927.320` —
  and GitHub moves that label on its own schedule, so the choice was between finding
  out what breaks on a branch or finding out later on `main` at a moment nobody
  picked.

  Something did break, which is the whole value of having asked: `CodSpeedHQ/action`
  v5 fails on 26.04 with `##[error]Unsupported system`. `mode: simulation` was
  already set and the action was pinned, so it is the image and nothing else. Every
  one of the five Radar runs CodSpeed, so every one of them would have broken the
  same way the day the label moved by itself.

  That job is pinned to **24.04 rather than left on `ubuntu-latest`**: left there it
  keeps working right up to the day the label moves and then fails on `main`. 24.04
  is supported until April 2029, and a comment beside it says to try 26.04 again now
  and then, because nothing here will notice when CodSpeed adds support.

  The risk surface was measured before anything changed — no `apt-get` and no `sudo`
  in any workflow, Python from `actions/setup-python` at explicit versions, no
  `container:` or `services:` jobs — and the Docker path was checked on its own by
  dispatching `docker-build-check.yml` against the branch, which succeeded on image
  `ubuntu26/20260927.149`.

  What pinning costs: nothing bumps it for you. Dependabot updates action versions,
  not `runs-on`.

- **ruff now lints `tools/` as well, because it never did.** Every one of the five
  Radar lints its package and its tests and stops there, which left
  `tools/security_exceptions.py` outside the check — the script that refuses a build
  over an unexplained alert had never been seen by the linter that gates the build.
  Found on 2026-10-02 by running ruff over the whole tree by hand while working on
  something else, which is not a way of finding things that scales.

- **The Italian comments are in English** — `Dockerfile`, `docker.yml`,
  `checker.py`, `cli.py`, `discover.py`, `gpg.py` and three test files. One
  comment in `docker.yml` had been half translated and ended mid-sentence.

- **The Docker build no longer races its own publish.** `docker.yml` and
  `publish.yml` both fire on the tag push, in parallel, and the Dockerfile
  installs `mailradar==<new version>` from PyPI. A fixed `sleep 60` stood in for
  the wait.

  mailradar never went red on it, which is exactly why this is here: apkradar had
  the identical step and lost the race twice — 2026.9.32 on 2026-09-24 and
  v2026.41 on 2026-09-30 — while mailradar published in the same minutes of the
  second one and passed on timing alone. The failure reads as
  `No matching distribution found`, listing versions up to the *previous*
  release, so it looks like a failed publish when PyPI already holds the files
  and only the index has not caught up.

  `.github/scripts/wait_for_pypi.sh` now polls with pip itself, which is what the
  Dockerfile uses and what the index answers for, for up to ten minutes. It runs
  *after* the version is extracted rather than before, because the tag is
  `v2026.41` while the distribution is `2026.41` and `==v2026.41` is not a
  version pip can ever find — where the `sleep` sat, there was nothing to wait
  for by name. Only on a tag push: the weekly rebuild of `latest` and a manual
  dispatch both name a version published long ago. Ported from cookieradar, which
  has polled since 2026-09-24, with its tests — `tests/test_ci_scripts.py` drives
  the script with a fake pip and pins where the step sits, what version it is
  given, and that nothing in the workflow waits by sleeping again.

## [2026.41] - 2026-09-29

### Fixed

- **The report no longer ends with a traceback.** Rich wraps `sys.stdout` in a
  `FileProxy` while a spinner runs and restores the stream without flushing it, so
  a partial line sat in that buffer until the proxy was garbage-collected — often
  during interpreter shutdown, where the message is
  `ImportError: sys.meta_path is None`. It appeared after a completed analysis, on
  a terminal only, and looked like the software failing at the worst possible
  moment. All eight spinners now flush both streams before they stop.

- **One pull request per CodeQL upgrade, not four.** The four `codeql-action`
  steps are pinned to a commit here, and Dependabot treats each path as its own
  dependency: on 2026-09-29 it opened #18, #19, #21 and #22 for the same
  4.38.1 → 4.38.2 bump, and every one failed with "Loaded a configuration file for
  version '4.38.1', but running version '4.38.2'" — each moved one step and left
  three behind, while CodeQL requires them to match. All four are on 4.38.2 now,
  and a `groups` entry keeps them moving together. mailradar was the only Radar
  exposed: the other four track the moving `@v4` tag, which hides the skew.

### Added

- **A CI gate that refuses.** Every other security workflow reports: `snyk.yml`
  carries `continue-on-error`, CodeQL and Docker Scout upload SARIF, and
  SonarCloud decides its quality gate after the job has already succeeded. On
  2026-09-29 all of them were green while ten high-severity alerts were open.
  `security-posture.yml` reads what they published and fails when a blocking
  finding has nobody's name against it; `SECURITY-EXCEPTIONS.toml` records the
  accepted ones, each with a reason and a review date. `sonarcloud.yml` now waits
  for its own quality gate, without which a red gate is a green job.

### Changed

- The prose is in English throughout. The quoted law stays in Italian, because
  that is the language it is read in.

## [2026.40] - 2026-09-26

### Changed

- **Nothing in the shipped package.** `mailradar/` is byte-identical to
  2026.09.12: no behaviour changes, no fixes, nothing to upgrade for. This
  version exists because the five Radar restarted from a common baseline, and a
  baseline that skips whoever had nothing to say would not be one. It is said
  here rather than left to be guessed from an empty diff.

- **Baseline: the five Radar restart from a common number.** They had drifted to
  .32, .12, .11, .6 and .3 of the same generation, which left the shared part of
  the version meaning nothing at all. The highest count in the suite was taken,
  rounded up for headroom, and every Radar starts again from 2026.40. From here
  the count belongs to each Radar again, and something urgent gets a third
  segment on top: 2026.40.1 before 2026.41.

- **The workflow named Tests now runs the tests.** It contained no pytest
  invocation: it installed the package and ran three CLI commands, two of them
  against a live domain, so the check required on every pull request depended on
  DNS and on somebody else's mail server. The suite was running inside
  `sonarcloud.yml`, on 3.12 only, which meant the four-version matrix here was
  proving that `mailradar --help` exits zero on four versions.

- PyYAML is declared. The tests read the workflow files and had been borrowing
  it from `mutmut` -> `libcst`, which on Python 3.13 requires `pyyaml-ft`
  instead — a fork that installs no module called `yaml`.

## [2026.09.12] - 2026-09-24

### Fixed
- **`mailradar batch` reads its list of domains as UTF-8.** It used a bare
  `open(file)`, so the locale chose the encoding. An internationalised domain is
  the ordinary case here, not an exotic one — `società.it` and `müller.de` are
  both registrable — and read through cp1252 the query went to a domain that
  does not resolve, reported as though it had been the one asked for. Three more
  defects in the same four lines: a byte order mark, which Notepad writes by
  default, became part of the first domain; an `OSError` that is not
  `FileNotFoundError` escaped as a traceback; and `#` was tested against the
  unstripped line, so an **indented comment was queried as a domain**.
- **One `GPGResult`, not two.** The class was declared in both `checker.py` and
  `gpg.py`, and the two were not the same: `gpg.py`'s carries a `fingerprint`
  field the other lacked. Since `lookup_gpg` returns `gpg.py`'s, a scanned
  `DomainReport` and a default-built one held different shapes in the same
  field. The duplicate is removed.
- **An unverifiable law now says what it costs.** The report warned that an act
  could not be fetched and separately printed `SHA256: non disponibile` against
  each citation, with nothing joining the two, so a missing hash read as a
  defect in the hashing. It is not: with no verified text there is nothing to
  hash.
- **`MAILRADAR_HOME` is no longer taken literally.** `~/cache` made a directory
  named `~`, a relative value followed the working directory so the cache
  stopped being one cache, and `"   "` became a directory name.
- `_discover_via_website` declared `extra_subdomains: list[str]` and defaulted
  it to `None`. The GPG lookup now pairs addresses with results under
  `strict=True`: `executor.map` yields one result per input, so the lengths are
  equal by construction, and this checks it rather than assuming it.

### Changed
- ruff, mypy, hypothesis and mutmut are development dependencies, with a
  `Quality` workflow running ruff and mypy on every push and pull request, and a
  weekly, non-blocking mutation run.
- Fifteen new properties checked against generated input: the DMARC and BIMI tag
  parsers read a string a domain owner writes by hand, and the email extractor is
  checked against its near-misses — `example.community` and
  `example.com.evil.org` must not match `example.com`.
- A contract test refuses any code in this repository that lets the locale
  choose a text encoding.
- **Every string the tool writes itself is now in English**, which the
  CHANGELOGs already were. The report's section is `Provisions applied` rather
  than `Norme applicate`, and finding titles, scope notes, evidence lines and
  the release script's messages follow. What the tool *quotes* is unchanged: a
  provision's text is fetched from the official Italian version of each act and
  hashed, so translating it would change every SHA-256 in every cache and report
  "the law changed" for every citation on the next run, for nothing.

## [2026.09.11] - 2026-09-21

### Fixed
- DMARC lookup walks up the domain hierarchy as required by RFC 7489 §6.6.3:
  when `_dmarc.<domain>` has no record, one label is removed at a time up to
  the organizational domain (`asufc.sanita.fvg.it` → `sanita.fvg.it` →
  `fvg.it`). Multi-label public suffixes such as `co.uk` are honoured, and the
  public suffix itself is never queried. An inherited record is reported with
  the domain it comes from, and the parent's `sp=` tag becomes the policy
  scored for the subdomain.

## [2026.09.10] - 2026-09-19

### Added
- `check` and `report` end with a "Provisions applied" section: each weakness
  cites the legal provisions it concerns, with the SHA-256 of the exact text
  applied and the date of that wording. The text is downloaded from EUR-Lex on
  every run and cached in `~/.mailradar/law_cache.json` (`MAILRADAR_HOME`
  moves the folder); a changed text is reported with its previous hash.
  Offline the cached copy is cited, or "SHA256: non disponibile". A failed law
  check never changes the result or the exit code.
  - GDPR art. 32: DMARC missing, weak SPF/DKIM, no GPG key on keyservers;
    art. 32(1)(a): MTA-STS missing or not enforced (mail may travel in clear).
  - NIS2, directive (EU) 2022/2555, art. 21: DMARC missing or MTA-STS missing
    (not for MTA-STS in testing mode). The report notes that NIS2 applies to
    essential and important entities only.

## [2026.09.9] - 2026-09-19

### Added
- `--version` option: `mailradar --version` prints `MailRadar <version>` and exits.
  The version is read from `mailradar.__version__`, the single source of truth
  also used by `pyproject.toml`.

### Fixed
- Docker: the `latest` image is now rebuilt every week from the most recent tag,
  without cache and pulling a fresh base image, so Debian security patches are
  picked up without waiting for a release. Versioned images are left unchanged.

### Security
- Docker: pip is upgraded before installing MailRadar and then removed from the
  final image. It is not needed at runtime and its vendored dependencies had
  known CVEs.
- `SECURITY.md`: the known open CVEs are now attributed to the correct base
  image (Debian Trixie) and the list was updated (OpenSSL is no longer
  affected).

## [2026.09.8] - 2026-09-16

### Fixed
- `send`: encryption with a key fetched from a keyserver failed because the key
  was never in the local keyring. The key is now imported into a throwaway
  temporary keyring, so the user's own keyring is left untouched.
- `send`: if a GPG key is found but encryption fails, the report is no longer
  silently sent in plaintext. It is not sent, the report is printed for manual
  delivery and the command exits with code 1.
- Total score could exceed 100 because the raw per-check maximums add up to
  more than 100. The raw score is now normalized to a 0-100 scale.
- DMARC and BIMI tag values containing `=` were truncated.
- An invalid DMARC `pct` value (non-numeric or outside 0-100) no longer crashes
  the analysis: it is reported as an issue and treated as 100 (RFC 7489 §6.3).
- A non-UTF-8 TXT record no longer crashes the analysis.
- `batch`: a domain that fails analysis no longer stops the whole run. It is
  reported and listed in a final "Failed" summary.
- `discover`: the email regex matched look-alike domains (e.g. addresses at
  `example.community` or `example.com.evil.org` when discovering `example.com`).
- `discover`: guessed role addresses (RFC 2142) are now shown separately as
  unverified candidates instead of being mixed with addresses found in public
  sources. They are skipped for domains that publish a null MX (RFC 7505).
- `discover`: GPG lookups for discovered addresses now run in parallel and
  also cover the guessed candidates.

### Security
- DNS records, domain names, keyserver data and report text shown in the
  terminal are escaped, so Rich markup injected via DNS records or other
  external data is no longer interpreted.

## [2026.09.7] - 2026-09-16

### Changed
- Bumped `anyio` from 4.15.0 to 4.15.1.
- CI: bumped GitHub Actions (`actions/checkout`, `actions/setup-python`,
  `docker/setup-qemu-action`, `github/codeql-action`) and aligned all CodeQL
  steps to v4.38.0.

## [2026.09.6] - 2026-09-15

### Changed
- Test coverage raised to 84%, with new tests for the CLI, `discover` and GPG
  modules.

## [2026.09.5] - 2026-09-11

### Changed
- Version bump only. No code changes since 2026.09.4.

## [2026.09.4] - 2026-09-11

### Added
- `release.sh` release automation script.

### Changed
- The Docker image and PyPI publish workflows now run on version tags (`v*`).
  The Docker workflow strips the `v` prefix and leading zeros from the tag to
  match the version published on PyPI.

### Security
- Docker base image moved from Debian Bookworm to Debian Trixie
  (`python:3.12-slim-trixie`) to address OpenSSL CVEs.

## [2026.09.3] - 2026-09-08

### Added
- `send --sign`: sign the outgoing report with the sender's GPG private key
  (clear-signed, using the `--from` address). The passphrase is asked
  interactively.
- `SECURITY.md` security policy with a vulnerability reporting contact and the
  status of known CVEs.
- Built distributions are GPG-signed in the PyPI publish workflow.
- Tests for GPG signing and SMTP sending.

### Changed
- CI: manual `workflow_dispatch` trigger for the publish and Docker workflows,
  SonarCloud analysis for Dependabot PRs, coverage reporting to SonarCloud,
  and CodSpeed benchmarks skipped on PRs that do not touch code.

### Fixed
- The publish workflow imports the signing key from a temporary file.
- Corrected the `codeql-action` commit hash in the Docker workflow.

## [2026.09.2] - 2026-09-06

### Added
- `report` command: generates a ready-to-send email report in Italian or
  English (`--lang it|en`) comparing each check's current state with the
  recommended configuration. Sender details are set with `--name`, `--role`
  and `--org` (placeholders otherwise). `--save` writes the report to a file.
- GPG public key lookup on keyservers (keys.openpgp.org, keyserver.ubuntu.com,
  pgp.mit.edu) for common contact addresses (`security@`, `dpo@`, `admin@`,
  `postmaster@`, `privacy@`). The result is shown as a GPG row in `check` and
  counts toward the score.
- `send` command: analyzes a domain and delivers the report. With a GPG key it
  encrypts the report for the key owner. Without one, it sends in plaintext to
  common security contacts over SMTP (`--smtp-host`, `--smtp-port`,
  `--smtp-user`, `--smtp-pass` or `MAILRADAR_SMTP_PASS`, `--from`). Without
  SMTP settings it prints the report for manual copy-paste.
- `check` verifies that the domain exists in DNS. If it does not, MailRadar
  scans common TLD variants and lets you pick one.
- `discover` command: finds email addresses for a domain from website scraping
  (common contact and privacy pages, including subdomains found via crt.sh
  Certificate Transparency logs), DNS (SOA and TXT records), RDAP and common
  role addresses. It reports which addresses have a GPG public key; skip that
  check with `--no-gpg`.
- Dockerfile and Docker image.
- Release workflows: PyPI publishing, Docker Hub image and GitHub Release.
- CI: CodeQL, SonarCloud, CodSpeed benchmarks, Trivy scanning and Dependabot.
  Dependencies pinned via `uv.lock` and a hash-locked `requirements-ci.txt`.
- Mock-based tests for the checker, GPG and reporter modules.

### Changed
- README examples no longer reference third-party domains.
- GPG keyserver lookups run in parallel and prefer the keys.openpgp.org VKS
  API, falling back to HKP. Before, domains with several candidate addresses
  could hit sequential timeouts.
- CI split into dedicated workflows, with GitHub Actions pinned to commit SHAs.

### Fixed
- Report templates are rendered with an explicit Jinja2 autoescape policy
  (`select_autoescape`: enabled for HTML, disabled for the plain-text `.j2`
  email templates).

### Security
- GPG encryption no longer uses `--trust-model always`.
- The keys.openpgp.org VKS endpoint is selected by parsing the keyserver
  hostname instead of a substring match on the URL.

## [2026.09.1] - 2026-09-04

### Added
- Email security checks for DMARC, SPF, DKIM, BIMI (with VMC detection),
  MTA-STS and TLS-RPT.
- DKIM detection across a list of common selectors, with accurate key size
  detection through the `cryptography` library.
- BIMI SVG logo validation over HTTP.
- MTA-STS policy mode detection.
- Score from 0 to 100 with grade levels (EXCELLENT, GOOD, MODERATE, POOR,
  CRITICAL) and a list of issues with recommendations.
- `check` command (`--verbose` shows raw DNS records) and `batch` command for
  a file with one domain per line.
- Color-coded Rich terminal output.

[Unreleased]: https://github.com/maksimtech/mailradar/compare/v2026.09.11...HEAD
[2026.09.11]: https://github.com/maksimtech/mailradar/compare/v2026.09.10...v2026.09.11
[2026.09.10]: https://github.com/maksimtech/mailradar/compare/v2026.09.9...v2026.09.10
[2026.09.9]: https://github.com/maksimtech/mailradar/compare/v2026.09.8...v2026.09.9
[2026.09.8]: https://github.com/maksimtech/mailradar/compare/v2026.09.7...v2026.09.8
[2026.09.7]: https://github.com/maksimtech/mailradar/compare/v2026.09.6...v2026.09.7
[2026.09.6]: https://github.com/maksimtech/mailradar/compare/v2026.09.5...v2026.09.6
[2026.09.5]: https://github.com/maksimtech/mailradar/compare/v2026.09.4...v2026.09.5
[2026.09.4]: https://github.com/maksimtech/mailradar/compare/v2026.09.3...v2026.09.4
[2026.09.3]: https://github.com/maksimtech/mailradar/compare/v2026.09.2...v2026.09.3
[2026.09.2]: https://github.com/maksimtech/mailradar/compare/v2026.09.1...v2026.09.2
[2026.09.1]: https://github.com/maksimtech/mailradar/releases/tag/v2026.09.1
