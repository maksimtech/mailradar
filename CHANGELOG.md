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

- **`check --headers mail.eml`: the DKIM selectors a message names.** DKIM keys were looked for under
  common selectors only, and bulk senders use others: a newsletter signed through Amazon SES, under a
  random 32-letter selector, read "DKIM not found" while its own `DKIM-Signature` named the selector in
  clear. Given a message the domain sent, `check` now asks first for the selectors of the signatures
  whose `d=` is the domain analysed (not the sending service's own), keeping only an `s=` that is a DNS
  name, and says which it found or that there were none. `analyze_domain` takes them as
  `dkim_selectors`. Tests use `tests/fixtures/mail/dkim_ses_newsletter.eml` and
  `tests/fixtures/dns/dkim_ses_selector.json` (both `_derived`, from a newsletter delivered on
  2026-11-18: the sender's domain replaced by example.com, a 1024-bit key as long as its own).
  Sources: [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376.html) §3.1 (selectors), §3.5 (the
  `DKIM-Signature` tags `d=` and `s=`).

- **MX of a domain that sends mail.** `check` now reads the domain's MX records (`MXResult`, no
  points). A domain that sends mail (SPF names a sender, or a DKIM key is published) and has no MX gets
  a note: replies and bounces go to its own address, and some spam filters score a From domain without
  MX. One with a null MX gets an issue: it declares it accepts no mail, and receivers may reject its
  mail with 550 5.7.27. A domain that sends nothing (`v=spf1 -all`, no key) gets neither, and an MX
  lookup with no answer says nothing and leaves the grade as it was. The letter (`report`, `send`) has an
  MX section only when there is something to say: the null MX as an action, with its reason, no MX as a
  note; neither brings the article 32 paragraph, which stays for DMARC, SPF and DKIM problems (#112).
  Tests use `tests/fixtures/dns/mx_kinds.json` (`_derived`: no recording has an MX
  answer); `example_com.json` and `startpage_com.json` gain the `MX` answers `analyze_domain` now asks for.
  Sources: [RFC 7505](https://www.rfc-editor.org/rfc/rfc7505.html) §3, §4.1, §4.2, the null MX;
  [RFC 5321 §5.1](https://www.rfc-editor.org/rfc/rfc5321.html#section-5.1), the implicit MX; the
  `MIME_FROM_MX_NONE` (+4.45) symbol in a message Infomaniak's rspamd delivered on 2026-11-19, why it
  matters to delivery (context, one receiver, not a measurement).

### Changed

- **Python 3.15 is supported, and 3.16 is the row allowed to fail.** 3.15.0 went final on 2026-10-09;
  it moves from the experimental `3.15-dev` row to the stable matrix and to the classifiers, and
  `3.16-dev` takes its place as the one row with `continue-on-error`, as in apkradar. The matrix jobs
  now report as `Tests (Python 3.11)` … `Tests (Python 3.16-dev)` rather than `test (3.11, false)`,
  so main's ruleset can require each stable row by a name that does not change with the matrix's
  other values (`tests/test_ci_contract.py`).
- **A short DKIM key names the rules it breaks.** A 1024-bit RSA key was told "upgrade to 2048-bit
  recommended", which reads as a preference. The issue now cites the rule written for DKIM, RFC 8301
  §3.2, which asks signers for at least 2048 bits, and NIST SP 800-131A Rev. 2, which disallows RSA
  under 2048 bits for generating signatures. A key under 1024 bits was "weak" with no length; it now
  says how many bits it has (`is a weak 768-bit RSA key`) and that, under RFC 8301 §3.2, verifiers must
  not accept signatures made with it: for receivers the domain has no working DKIM. That branch had no
  test: it now has one, on a 768-bit key made for `tests/fixtures/dns/dkim_short_key.json`
  (`_derived`, since no recording has one). No score changes (the score of a key under 1024 bits is
  #111).
  Sources: [RFC 8301 §3.2](https://www.rfc-editor.org/rfc/rfc8301.html#section-3.2), the DKIM rule;
  [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final), the signing rule;
  [dmarcdkim.com, "Cracking a 1024-bit DKIM key"](https://dmarcdkim.com/blog/cracking-a-1024-bit-dkim-key)
  (2026), why it matters now: from the GPU factorings of RSA-260 and RSA-896 it estimates RSA-1024 at
  about 1,000 GPU-years. That figure is a vendor's extrapolation, cited for context, not a measurement.

- **Every job has a time limit, so a hung job no longer holds a pull request for six hours.** No job
  but mutmut set `timeout-minutes`, and GitHub's default is 360 minutes; on a required check the pull
  request waited that long. Each limit is about three times the job's longest run in its last 40 (ten
  minutes at least): 15 for SonarCloud, 20 for the image, 10 for the rest. Two jobs wait on purpose
  and get more than their runs suggest, so they still say what they were waiting for: Security
  Posture 30, past the 20 minutes it waits for the scanners, and publishing 30, past the 15 minutes
  it waits for PyPI to show and install the new version; the test reads both waits from the
  workflows (`tests/test_job_timeouts.py`, maksimtech/apkradar#113).

- **Mutation testing runs again, and a test catches the next gap on the pull request.** The run of
  2026-11-21 stopped collecting: `tests/test_lock_agreement.py`, since 2026-11-17, reads
  `requirements-ci.txt`, which mutmut did not copy into `mutants/`. It is now in `also_copy`. This was
  the fourth run lost the same way since 2026-10-03, each found on a Saturday: `tests/test_mutmut_copy.py`
  reads the tests for the files they join to the repository root and fails when one that exists is
  not copied. Verified by rebuilding `mutants/` from mutmut 3.8's copy rules and running the suite
  inside it: 1172 passed.

- **Docker Scout no longer fails on GitHub's anonymous rate limit.** docker/scout-action downloads
  its ~190 MB binary from api.github.com without authentication, on the 60-an-hour budget of the
  runner's address, which GitHub-hosted runners share; when others have spent it the scan fails with
  "Unexpected HTTP response: 403" before looking at the image, and Security Posture after it is
  skipped. `.github/scripts/fetch_scout_binary.sh` now fetches the binary with the job's token first
  and puts it where the action uses a binary already in place, after checking that the release tag
  is the pinned commit and that the file has the SHA-256 GitHub publishes; a mismatch stops the job.
  In the image workflow it runs before the checkout of the tag being built, which an older tag would
  not have. Same as maksimtech/apkradar#122, tried on main there (`tests/test_scout_binary.py`).
  Sources: [docker/scout-action#116](https://github.com/docker/scout-action/issues/116).

- **Coverage reaches this repository's Codecov project again.** The upload authenticated with a
  `CODECOV_TOKEN` secret, and Codecov files an upload under the project its token belongs to: the
  secret here held exeradar's token, so every report since at least October went to exeradar's
  project, and `codecov/patch` on this repository's pull requests had nothing of its own to compare.
  The upload now uses OIDC (`use_oidc: true`, `id-token: write` on the test job): GitHub tells Codecov
  which repository the job runs in, and there is no secret left to mix up. The test that required the
  token now requires OIDC and forbids the secret (`tests/test_ci_contract.py`).

### Security

- **CVE-2026-121482 (OpenSSL, CRL distribution points) is accepted until Debian ships a fix.** Docker
  Scout reported it on 2026-11-21: a certificate with very many CRL distribution points, verified with
  CRL checking enabled, costs CPU time quadratic in their number (openssl/openssl#33546; no advisory
  yet, no fixed Debian package). It is not reachable here: the only TLS context mailradar builds is
  `ssl.create_default_context()`, which enables no CRL checking, and nothing adds it. Reviewed on
  2026-12-15 with the other OpenSSL entries (maksimtech/apkradar#124).

- **CVE-2026-124709 (OpenSSL, QUIC) is accepted until Debian ships a fix.** Debian moved trixie to
  openssl 3.5.9-1~deb13u1, which a fresh build installs, and on 2026-11-21 Trivy reported the issue
  against it; Docker Scout never had here, so it had no entry and Security Posture failed. 3.5.9 does
  not fix it (fixed upstream in 3.5.10; Debian has no fixed trixie package), and it is not reachable:
  Python's ssl exposes no QUIC and mailradar runs no server. The entry holds for any scanner. Reviewed
  on 2026-12-15 with the other OpenSSL entries.

- **Three OpenSSL issues are accepted until Debian ships a fix.** At the first scan of main since
  2026.48 (2026-11-20), Docker Scout reported CVE-2026-107496 (advisory of 2026-11-10),
  CVE-2026-107493 (advisory of 2026-11-17) and CVE-2026-84786 (a DANE client crash, no OpenSSL advisory
  yet, fix in openssl/openssl#33634) as high against the base image's openssl 3.5.7-1~deb13u3, and
  Security Posture failed. Debian has no trixie package with any of the fixes. None is reachable here:
  they need `CMS_encrypt()`, a stack passed to `PEM_X509_INFO_read_bio_ex()`, or a TLS client with
  DANE enabled, and Python's ssl does none of these; mailradar reads no TLSA record. The other four
  issues of those advisories, accepted in the other Radars, are not reported here and get no entry,
  since an unused one fails the gate. Reviewed on 2026-12-15.

- **Two glibc issues Debian has already fixed are accepted for Docker Scout until this release is
  published.** On 2026-11-21 Docker Scout reported CVE-2026-19499 (`strfmon()`) and CVE-2026-5435 (the
  deprecated resolver printing functions) as high against glibc 2.41-12+deb13u4 in the image published
  for 2026.48, and Security Posture failed. Debian fixed both for trixie in 2.41-12+deb13u5; the image
  built from this source runs `apt-get upgrade` and has it, and Trivy, which reads that image, does not
  report them. Neither is reached here anyway: Python's `locale.currency()` does not call `strfmon`, and
  mailradar's DNS is dnspython, which prints no record through libresolv. The entries are reviewed on
  2026-12-08 and fail the build as unused once the new image is out.

## [2026.48] - 2026-11-17

### Added

- **SPF says what its ranges authorise and how many lookups it spends.** Seen in qnap.com's record on
  2026-11-16: `ip4:113.196.74.98/27` is written from an address inside the range, and RFC 7208 §5.6
  compares only the first 27 bits, so all 32 addresses of 113.196.74.96/27 are authorised; the same
  range is listed again in `include:_ac.qnap.com`. Both are now reported as notes, in the new
  `SPFResult.notes`, not as issues: the letter prints "SPF — Action required" whenever `issues` is not
  empty, and a record that works needs no action. The note says what the qualifier does to the whole
  range: `ip4:` authorises it, `-ip4:` denies it, `~ip4:` softfails it, `?ip4:` marks it neutral. The
  address written is compared with the network's first, not the text, so an aligned range spelled
  otherwise (`2001:DB8::/64`) raises nothing. A range is called redundant only when the evaluation
  reaches the other range first for every address it covers (§4.6.2, §5.1: the first match decides,
  nothing after `all` is tested): not when that range comes after an `all`, or after a term that may
  fail, softfail or neutralise those addresses first, in the record that lists it or in any record
  above it on the way, nor through an include that does not pass, at any depth, since `?include:`,
  `~include:` and `-include:` match with their own qualifier (§5.2). When in doubt, nothing is
  claimed. The note names the term of the domain's own record (`include:a.example.net`, or its
  `redirect=`), with the records in between (`through b.example.net`). The lookup count, compared with
  the limit and then dropped, is kept in `SPFResult.lookups` (None when not counted), and a record at
  10 of 10 gets a note: the next include breaks it. An `include:` or `redirect=` whose target is a
  macro is counted and not followed, so the count is then a lower bound: `SPFResult.lookups_partial`
  says so, and the note reads "at least N". The included records are compared from the queries the
  count already makes, each asked once, so no DNS query is added. No score changes.

### Changed

- **`+a` and `+mx` are no longer called too permissive.** They authorise the domain's own A and MX
  hosts, which is what most records mean to do, and RFC 7208 §4.6.2 makes `+` the default qualifier:
  `+a` is the same term as a bare `a`, which was never flagged. The warning judged the spelling, not
  the record, and marked as permissive a `-all` record that is not.

- **A usage error exits 64, not 2.** Click exits 2 on an unknown option or a missing argument, and 2 is also
  `check`'s grade CRITICAL: a script could not tell a wrong command line from a critical domain. Every usage
  error, at any level and in every command, now exits 64 (EX_USAGE, sysexits.h), and so do the new refusals of
  a value: `--lang de`, a URL or an address instead of a domain, `--sign` without `--from`. The grade codes
  0-3 are unchanged; the README's table lists 64.

- **`batch` exits with the worst code `check` would give.** It exited 0 whatever it found. It now exits with
  the highest of the codes `check` would give each domain, a domain it skipped (not a domain, not in DNS,
  analysis failed) counting 1 as in `check`: 0 only when every domain was analysed and graded GOOD or better,
  2 when the worst is CRITICAL, 3 when an analysis could not be completed.

- **No published GPG key is a suggestion, not a GDPR art. 32 gap.** Owner's decision: art. 32 asks for
  measures appropriate to the risk, and a key on a keyserver is not one of them. `law_checker` no longer cites
  art. 32 for it and prints a suggestion instead; the letter's art. 32 paragraph appears only when it lists a
  problem with DMARC, SPF or DKIM, and not for a domain whose only findings are BIMI, MTA-STS, TLS-RPT, SPF
  notes or the missing key.

### Fixed

- **An SPF syntax error is a permerror, and the issue shows the term.** RFC 7208 §4.6: a syntax error
  anywhere in the record makes receivers return permerror and apply no SPF. MailRadar dropped the
  term and scored the rest, so `v=spf1 ip4:192.0.2.0/24 foo:bar -all` got the full 20 points, and a
  typo of `all` (`-al`, `-all;`) read as "SPF has no all mechanism". Now an unknown mechanism
  (`foo:bar`, `1x`), a typo of `all`, `redirect=` or `exp=` twice or with no domain, a qualifier on a
  modifier, a known mechanism in a form §5 does not allow (`a/33`, `mx;`, `include:` with no domain),
  and an `ip4:`/`ip6:` value outside the grammar of §5.6 are a permerror scored 0. Python's
  `ip_network` accepted a netmask, a hostmask, a leading zero (`/027`) and an IPv6 zone id, none of
  which is SPF. A modifier with an unknown name (`foo=bar`) stays allowed (§6). The same holds for a
  record an `include:` or `redirect=` pulls in.

- **An `include:` whose target has no SPF record is a permerror.** RFC 7208 §5.2 makes it one
  whenever the include is evaluated, as it does for a target with two records. It is a common
  leftover after a change of provider, and it scored 20 without a word. The issue names the include,
  and the check scores 0, as for a `redirect=` to such a name. An include that gets no answer stays
  "not verified", not a permerror.

- **A passing range of every address scores as `+all`.** `ip4:0.0.0.0/0`, `ip6:::/0`, or any passing
  range of prefix length 0, lets every server of the family pass, and before `-all` it scored 20. It
  now scores 0 and is reported as `+all` is, also in a record a `redirect=` hands the verdict to.

- **A `redirect=` with a macro counts towards the 10 lookups.** It was left out of the count because
  its target could not be named, so `v=spf1 a mx`, seven `a:` and `redirect=%{d}.r.example.net` was
  counted 9, not 10, and a record one lookup past the limit passed as valid. A record whose verdict
  is handed to such a `redirect=` was also told "SPF has no all mechanism — the default result is
  neutral", although the redirect applies; the issue now says the verdict is the macro target's,
  which is not checked. The score of that case is unchanged.

- **A citation is "verified" only when the reference it cites is in the text downloaded now.** The
  check looked at the article: with Cellar's page parsed and point a) of GDPR art. 32 laid out as a
  paragraph instead of a label/text table, `32(1)(a)` was missing from the fresh text and fell back to
  the cache, old SHA-256 and date included, under "verified against Cellar"; with an empty cache the
  same label stood beside `SHA256: not available`. Every cited reference is now looked up in the text
  just parsed, and one that is missing makes the act a fetch failure: its citations come from the cache,
  labelled as such, or have no hash and say so.

- **A failed download always reaches the EUR-Lex fallback and the cache.** Only `httpx.HTTPError` was
  turned into a fetch failure. A 303 to `http://xn--/DOC_1` makes httpx raise `idna.core.IDNAError`, a
  `ValueError`, which skipped the fallback and ended the whole law check even with the cache populated.
  `httpx.InvalidURL` and `ValueError` are now fetch failures too.

- **Redirects stay on the source's host.** Any `Location` was followed, so a text served by another
  host was labelled "verified against Cellar". Cellar may redirect only to publications.europa.eu,
  EUR-Lex only to eur-lex.europa.eu and Normattiva only to www.normattiva.it, on the default port; the
  http:// hop Cellar makes is still taken over HTTPS. Any other target ends the fetch before a request
  is sent to it, and the hosts in `docs/nis2-compliance.md` are now the only ones the law check can
  reach.

- **A page is read up to 32 MiB, and a fetch ends after 120 seconds.** The timeout bounded each read,
  not the whole: a server sending a byte every few seconds held the audit for as long as it liked, and
  nothing limited the size of the page. The body is now streamed, refused past `MAX_RESPONSE_BYTES`
  (32 MiB; the GDPR from Cellar is 823981 bytes) and abandoned past `FETCH_DEADLINE` (120 s, redirects
  included); either one is a fetch failure, so the fallbacks apply.

- **A change in the law is reported even when the cache cannot be written.** The comparison with the
  previous text was made by the save, so with a read-only cache a law whose text changed was cited
  without the warning, and an unchanged wording was dated to the day of the audit. The merge is now
  `law_cache.merge`, made before the save and kept whether the save succeeds or not.

- **Errors and statuses name the source that was tried.** A missing article always read "not found in
  the EUR-Lex page", for Normattiva and Cellar pages too; it now names the source. `LawFetchError`
  carries `source` and `reached`, and `ActStatus` carries `tried` ("Cellar", "Normattiva", "Cellar and
  EUR-Lex") and `failure` ("unreachable", or "not_in_text" when a page came back without the text
  cited), with `reason` as a report should say it: "Cellar answered without the text cited" rather
  than "EUR-Lex unreachable".

- **The NIS2 scope note goes with a NIS2 citation.** The note on D.Lgs. 138/2024 was added whenever
  DMARC or MTA-STS was not present, including when their DNS lookup had failed and nothing was cited.
  It is now derived from the findings, so it appears exactly when art. 24 of the decree is cited.

- **A corrupt law cache is an empty one.** A deeply nested `law_cache.json` made `json.loads` raise
  `RecursionError`, which is neither `OSError` nor `ValueError`, and the whole law check failed. It is
  now read as an empty cache, like any other unreadable file.

- **Normattiva's "-bis" paragraphs can be cited.** Paragraph numbers were read as `\d+`, so paragraphs
  3-bis and 4-bis of art. 21 of the Consumer Code were part of the article's text and had no reference
  of their own. `21(3-bis)` and `21(4-bis)` now exist, as do -ter, -quater and the later Latin
  numbers (every one after quater ends in -ies), with their lettered points.

- **A malformed BIMI URL no longer ends the analysis.** `default._bimi` publishing
  `l=https://[::1/logo.svg` made `urlsplit` raise `ValueError: Invalid IPv6 URL`, and a port past
  65535 did the same on `.port`; nothing caught either, so `analyze_domain` stopped for the whole
  domain. A logo URL that cannot be parsed is now a BIMI issue ("logo URL is malformed") and is not
  fetched. `a=` was counted as a VMC whatever it held: it now has to be a well-formed `https://` URL,
  or it earns no VMC points and says why.

- **The BIMI logo filter catches every IPv4 literal `getaddrinfo` reads.** `https://127.1/`,
  `https://2130706433/`, `https://0x7f000001/` and `https://0177.0.0.1/` passed as host names, since
  `ipaddress` reads only dotted quads, while glibc's `inet_aton`, which `getaddrinfo` tries before
  DNS, reads all of them as 127.0.0.1: in the Docker image the logo fetch reached the loopback. A host
  made of numbers alone is now parsed the way `inet_aton` parses it (one to four parts, decimal, octal
  or hex) and fetched only if that gives a global address; numbers that give no address are not
  fetched either. Host names are still not resolved before the fetch, as the README says.

- **DKIM scores a key only once it decodes as one.** The key size used to fall back to the length of
  `p=`: a 2048-bit key cut at 255 characters scored as 1024-bit (10 points), `p=` plus 400 `A` as
  2048-bit (15), `v=DKIM1; k=rsa` with no `p=` as a weak 0-bit key (3), an RSA key under `k=ecdsa` as
  2048-bit (15), and a DMARC record under a selector, matched because it holds `p=`, as 512-bit RSA.
  A key that does not decode as its declared type (SubjectPublicKeyInfo or PKCS#1 for RSA, 32 bytes
  for Ed25519), an unknown `k=`, or a record with no `p=` (RFC 6376 §3.6.1 requires it; an empty `p=`
  is still a revoked key) is now "malformed — signatures cannot be verified" and scores 0. Only
  `v=DKIM1` records, or records without `v=` that carry DKIM tags, are read as keys. A malformed key
  verifies nothing and lets nobody forge, so beside a working key it is reported without setting the
  score: the posture is the weakest key that works. `DKIMResult.keys` names it `malformed RSA key`.

- **A DKIM key in testing mode is no longer full marks.** RFC 6376 §3.6.1: verifiers must not treat
  mail from a signer with `t=y` differently from unsigned mail. Such a key is reported, and scores 0
  unless another key without `t=y` works; `DKIMResult.keys` marks it `(testing, t=y)`.

- **MTA-STS reads the record and the policy as senders do (RFC 8461 §3.1, §3.2).** A policy file
  holding only `mode: enforce`, one with `version: STSv2`, two `v=STSv1` records and a record with no
  `id=` each scored 5 with mode enforce, and any record containing `v=STSv1` counted. Now only
  records that begin with `v=STSv1` count; none, several, or one without a valid `id=` mean no policy,
  and the file is not fetched. The policy needs `version: STSv1`, `mode`, `max_age` and, in enforce or
  testing mode, an `mx`: without them it is no policy, scores 0, and the issue names what is missing.
  `MTASTSResult.mode` is set only from a valid policy.

- **TLS-RPT follows RFC 8460 §3.** `v=TLSRPTv1;` with no `rua` scored 3, so did two TLS-RPT records
  (senders then assume none), and `rua=https://x.example/?rua=1;` was read as `rua='1'`, from the last
  `rua=` in the text. The record is now parsed as tags, needs a `rua` with at least one `mailto:` or
  `https:` URI, and several records count as none.

- **DMARC discovery asks the domain and its organizational domain, nothing in between.** RFC 7489
  §6.6.3 queries `_dmarc.<domain>` and, if it has no record, `_dmarc.<organizational domain>` (from the
  Public Suffix List). MailRadar removed one label at a time: for `sub.a.example.com` it reported the
  `p=none` of `_dmarc.a.example.com`, while receivers apply `example.com`'s `p=reject`. The
  intermediate names are no longer queried, and `found_at` shows where the record was found.

- **An invalid DMARC `p=` or `sp=` is no longer shown as the policy.** `p=rejected` became
  `policy='rejected'`, an empty `p=` became `''`, an inherited `sp=bogus` became `'bogus'`. As §6.6.3
  says, a record with no valid `p` (or an `sp` that is not valid) acts as `p=none` when its `rua`
  names a valid URI, and otherwise no DMARC applies; the issue names the value. `rua=a@example.com`,
  an address without `mailto:`, earned the 3 points of reports configured: entries that are not URIs
  now count for nothing and are reported.

- **A name DNS cannot hold is no longer reported as a DNS failure.** dnspython raises `LabelTooLong`,
  `NameTooLong` and `IDNAException` as `DNSException`s, so they became `DNSLookupError`, "DNS lookup
  failed", and `check` suggested trying again or another resolver. `domain_exists` and the checks now
  raise `InvalidDomainError` (a `DNSLookupError`, so existing callers still catch it) saying the name
  is not a valid domain name and why, without asking a resolver. A domain so long that every
  `<selector>._domainkey.<domain>` passes 255 octets is told that no DKIM selector can be checked,
  rather than left not verified for ever; `_dmarc.<domain>` past the limit falls back to the
  organizational domain.

- **BIMI earns nothing while DMARC does not enforce.** Mail clients show a BIMI logo only under DMARC
  quarantine or reject, and `p=none` beside a logo and a VMC scored 10 of 10 with no issue.
  `analyze_domain` now withholds BIMI's points when the DMARC policy that applies is neither, and says
  so; the dependency lives there, where the two results meet.

- **An HTTP request that gets no answer leaves its check not verified.** As for DNS since 2026.47,
  "not measured is not zero": a policy fetch that timed out scored MTA-STS 0 with "policy file not
  accessible", and graded the domain. A transport error (timeout, reset, a refused connection) on the
  MTA-STS policy or the BIMI logo now sets the check's `error`, so `total_score` is None and `report`
  and `send` refuse. An HTTP status such as 404 is the domain's server answering and stays a finding;
  so does a connection that fails because DNS has no address for the host (`mta-sts.<domain>` never
  set up), which is checked with one A/AAAA query after the failure.

- **Informational SPF findings are printed and written as notes.** `SPFResult.notes` holds what is not a
  problem — a range written from an inner address, a range an include already authorises, 10 lookups of 10.
  `check` prints them under "Notes", apart from the issues and through the same sanitising; the letter lists
  them as "Note:"/"Nota:" in the SPF section, which stays "Properly configured" when they are all there is.

- **`--sign` that fails stops the send.** A wrong passphrase, or no secret key for the address, sent the report
  unsigned without a word (`sender.py`, the signature was used only if there was one), and `--sign` without
  `--from` signed nothing and said nothing. A failed signature now ends `send` with exit code 1 and the reason;
  `--sign` without `--from` is a usage error, refused before the analysis. The passphrase is asked before the
  "Checking GPG keys and sending" spinner starts, not under it, where the status line was redrawn over the
  prompt.

- **SMTP failures are told apart, and a sent report counts as sent.** Every exception meant "try the next
  address": a wrong password (535) cost five logins on five connections, which is how an account gets locked,
  and a server that accepted the message after `DATA` but answered `QUIT` with 250 instead of 221 made
  `SMTP.__exit__` raise, so the report was delivered five times and the user told it had not gone. Only a
  refused recipient now moves on to the next address; authentication, TLS and connection errors end the
  attempt at once and are reported with the server's answer. A message accepted after `DATA` is sent, whatever
  `QUIT` gets back. Whenever delivery was configured and did not happen `send` exits 1, in every branch, and an
  encrypted report whose SMTP delivery failed is no longer printed under "no SMTP configured".

- **`send` can use STARTTLS.** `use_tls` was never set from the command line, so on port 587 the TLS handshake
  met a plain-text greeting five times and the command exited 0. `--smtp-starttls` connects in plain text and
  upgrades with STARTTLS, and port 587, the submission port (RFC 6409), uses it without being told; the
  certificate and the host name are verified either way.

- **`report`, `send` and `batch` check the name before analysing it.** Only `check` asked DNS whether the
  domain exists: `report no-such-domain.example` wrote a letter grading it CRITICAL, and `send` would have
  mailed security@ it. `report` and `send` now go through `check`'s handling — not found, no answer from DNS,
  TLD variants to choose from — and `batch` reports a name that does not exist as failed, without prompting.
  A URL (`https://example.com/`) or an address (`security@example.com`) is refused in every command, with the
  host or the domain to pass instead.

- **`send` and `discover` use the name as analysed.** `send StartPage.COM.` sent
  `RCPT TO:<security@StartPage.COM.>` and titled its panels with the raw argument; `discover` queried crt.sh,
  the website and RDAP with it. Both now use the lower-case name without the trailing dot.

- **`--lang` is `it` or `en`, in any case.** On Windows `--lang IT` found `report_IT.j2`, since NTFS ignores
  case, while the code compared `lang == "it"`: an Italian letter with English lines in it, saved as `_IT.txt`.
  `--lang de` gave an English letter saved as `_de.txt`. Other values are now refused, and `generate_report`
  no longer hides a template that is missing or broken behind `except Exception` and an English fallback.

- **The Score column says what was measured, on each check's own scale.** A check whose lookup got no answer
  showed 0; it shows `—`. Each check's points were coloured on the 0-100 scale of the total, so a perfect SPF
  (20 of 20) came out red; they are coloured by their share of `MAX_SCORES[check]`.

- **The letter says what was found.** A malformed Ed25519 DKIM key was told to "Upgrade to RSA 2048-bit"; the
  letter now says the key is malformed and asks for it to be republished. A declined BIMI (`v=BIMI1; l=; a=;`)
  was "present but with errors" with a record to publish; it is reported as the domain's choice, with no
  recommendation. An incomplete analysis no longer reads "None/100". The mailed body no longer repeats the
  "Subject:"/"Oggetto:" line under the Subject header; `report` still prints it, for whoever copies the letter.

- **Records are printed as published.** Rich read `:100:` as the emoji shortcode for 💯, so
  `ip6:2001:db8:100::/48` showed as `2001:db8💯:/48`, in the table and under `--verbose` alike. The console no
  longer replaces emoji shortcodes.

- **`discover` reports the keyservers that did not answer, and reads addresses whole.** A keyserver error was
  dropped, so "No GPG public keys found" was printed when the keyservers had answered 429; those addresses are
  now listed as not verified. The address pattern cut local parts — `o'brien@` to `brien@`, `josé.dpo@` to
  `.dpo@`, `mailto:%20dpo@` to `%20dpo@` — and reported the cut: it now reads RFC 5322's dot-atom (with the
  letters of other scripts RFC 6532 allows), decodes `mailto:` values, and leaves out a local part that is not
  valid. An SOA contact with an escaped dot (`john\.doe.example.com.`, RFC 1035 §8) was dropped; it is
  `john.doe@`.

- **A keyserver index entry past its expiration date is not a key.** `_machine_readable` read the `r`, `d`
  and `e` flags and ignored the expiration field: a key a keyserver had not flagged was taken although gpg
  cannot encrypt to it.

- **A 429 from keys.openpgp.org is not lost when keyserver.ubuntu.com answers.** The lookup returned the
  unverified key and forgot that the keyserver that verifies addresses had not answered. `GPGResult.unanswered`
  keeps it, the issues say a verified key may exist, and `send` repeats it when it refuses the key.

- **What one fix found, the others now say in their own words.** The bug-fix pass of 2026-11-17
  changed what the checks find, and four places still spoke of the old answers. A DKIM key that
  cannot be used, malformed or only in testing mode, was shown as `0-bit RSA` with a ✅, described by
  its length in the letter and cited as `DKIM 0 bit`; it is now named as the check describes it
  (`malformed RSA key`, `chiave RSA malformata` in Italian, `(testing, t=y)`), marked ❌, and cited
  as such, through `checker.dkim_unusable`. A record made permissive under `-all` by a pass /0 range
  was cited as `SPF -all`, which reads as the remedy; it is now `SPF authorises every address before
  -all`, and a record with no `all` that applies is no longer cited as `SPF permissivo`. A law text
  whose source was reached but lacked the point cited was printed as `EUR-Lex unreachable` whichever
  source was tried; the CLI now prints the reason the status carries. And `check` answered a name
  DNS cannot hold with "try again, or with another DNS resolver"; it now says the name is not a
  valid domain name, with exit code 64, as for any other usage error.
  `tests/test_findings_named_as_they_are.py` holds the cases.

### Security

- **Text from outside no longer reaches the terminal as commands.** `rich.markup.escape` neutralises `[tag]`
  and nothing else, and Rich strips only BEL, BS, VT, FF and CR: an ESC in a DNS TXT record, a keyserver's
  answer or an MTA-STS policy went to the terminal as it was, in the table, the issues, `--verbose` and the
  letter's panel. A record such as `v=spf1 \x1b[2J\x1b]8;;https://evil.example\x1b\click\x1b]8;;\x1b\ -all`
  cleared the screen of whoever audited the domain and put a hyperlink in the output. C0 controls, DEL and C1
  controls are now written out (`\x1b`) before anything from outside is printed, in `check`, `check -v`,
  `batch`, `report`, `send` and `discover`, and in the letter that is saved or mailed.

- **`send` encrypts on its own only to a key whose address was verified.** It encrypted to the first key any
  keyserver listed, keyserver.ubuntu.com included, where anyone can upload a key under any address: the report
  could go to whoever uploaded it. Owner's decision: a key from keys.openpgp.org (its owner confirmed the
  address) is used as before; one from keyserver.ubuntu.com only with its fingerprint confirmed through the
  new `--gpg-fingerprint` option, which must match the key found, and gpg then encrypts to that fingerprint and
  no other. Without it nothing is sent, neither encrypted nor in plaintext, and `send` prints the fingerprint,
  the reason and the report for a manual send, with exit code 1. Given when no key is found at all, the
  option stops the send too, rather than letting it go in plaintext.

- **`discover` follows redirects by hand, to public https only.** With `follow_redirects=True` on crt.sh, the
  website pages and RDAP, a redirect could send the tool anywhere, `http://127.0.0.1` included. A redirect is
  now followed only to `https://`, and only to a host of the same registrable domain as the first request or to
  one whose addresses are all public; a 302 to `http://127.0.0.1:8080/admin` is not requested.

- **`report --save` writes where it says, under a plain name.** The file name was built from the raw argument:
  `x/../../../evil.com` wrote outside the current directory, `example.com:x` wrote an NTFS alternate data
  stream, and `https://example.com/` ended in an uncaught OSError. The name is now
  `mailradar_<domain>_<date>_<lang>.txt` in the current directory, `<domain>` the analysed name reduced to
  `a-z`, `0-9`, `.` and `-`; a file that cannot be written is reported, with exit code 1.

- **gpg stays local, and stops what it started.** Encrypting to a key that turned out unusable (expired,
  say), gpg's default `auto-key-locate local,wkd` looked the address up through WKD at `openpgpkey.<domain>`,
  and the dirmngr it started kept running after the throwaway homedir was deleted. `send` now passes
  `--auto-key-locate clear,local` and `--no-auto-key-retrieve`, and runs `gpgconf --homedir <dir> --kill all`
  before the homedir goes.

## [2026.47.1] - 2026-11-17

### Changed

- **`uv.lock` and `requirements-ci.txt` name the same versions again.** Dependabot's pip ecosystem
  bumps only `requirements-ci.txt`, so from 2026-09-14 seven packages drifted apart one pull request
  at a time, and `uv lock --check` cannot see it, because it compares `uv.lock` with `pyproject.toml`.
  `uv.lock` now has anyio 4.16.0, certifi 2026.10.23, cryptography 50.0.2, idna 3.20, markupsafe
  3.0.4, pycparser 3.12 and typer 0.27.3, as `requirements-ci.txt` does. Every one of them is past
  the 14-day rule, and PyPI lists no known vulnerability on either side. `tests/test_lock_agreement.py`
  fails when the two files disagree on a package they both pin.

- **The sqlite3 findings say what Debian decided, and Trivy's two new ones are recorded.** On
  2026-11-09 Trivy began reporting CVE-2026-119374 and CVE-2026-119379, which only Docker Scout had
  reported, and Security Posture failed on main. Both now have a Trivy entry beside the Scout one.
  The sqlite3 entries also said there was no fixed version anywhere and that they waited for Debian:
  Debian has since fixed the three CVEs in sid (3.54.1-1) and marked them no-dsa for trixie, so no
  trixie update will come. They stay accepted on the ground they already gave, that no code of the
  project reaches the flawed parts of SQLite, until 2026-12-31, when the question becomes a base
  image with a fixed sqlite3.

- **Dependabot proposes a release once it is 14 days old, and actions arrive as one pull request.**
  The Radar take a dependency at least 14 days after its release unless a known vulnerability makes the
  older version the risk; without a cooldown Dependabot opened twelve pull requests across the Radar on
  2026-10-29 and 2026-11-02 for releases two to thirteen days old. `.github/dependabot.yml` now sets a
  14-day cooldown on every ecosystem — Dependabot's security updates are not subject to it — and groups
  the GitHub Actions updates into one weekly pull request. `tests/test_dependabot_config.py` holds both.

- **Trivy scans the image a pull request builds; Snyk is gone.** As in maksimtech/apkradar#54: of what
  `snyk.yml` ran, only the container scan worked. Snyk Open Source stopped on `SNYK-OS-PYTHON-0013`
  ("Missing required packages") here too, so its check on new dependency issues let everything through;
  Snyk Code repeated CodeQL, Bandit and SonarCloud; and the free plan's monthly test quota, shared by the
  Radar, was spent. `trivy.yml` now builds the image and scans it before merge, with no token and no
  quota. The Snyk-sourced entries left `SECURITY-EXCEPTIONS.toml`, their reasons moving into the entries
  of the scanners that still report the same CVEs; `tests/test_trivy_workflow.py` holds the image scan,
  and `tests/test_workflow_set.py` keeps `snyk.yml` retired.
  Its first run reported ten CVEs in the base image's Debian packages (util-linux ×4, ncurses, systemd, perl, sqlite3, acl, and gnupg2 in the gpg this image adds), all
  without a fix in trixie and none in code this tool runs; with the three sqlite3 CVEs Docker Scout raised
  on `main` on 2026-11-02, which had turned Security Posture red, they are recorded in
  `SECURITY-EXCEPTIONS.toml` to wait for Debian, as the maintainer decided that day for every Radar.

- **The author address published on PyPI is the project alias, github@maksimtech.com.** It was a
  personal mailbox, which PyPI shows to anyone and bulk senders harvest: on 2026-10-31 a cold "patch
  offer" from a mass-mailing account reached it. Releases already published keep the old address;
  the next one carries the alias. `tests/test_package_metadata.py` keeps it that way.

- **The image is built on Python 3.14.** It was built on `python:3.12-slim-trixie`; 3.12 has had
  security fixes only since April 2025 and 3.13 joined it in October 2026, while 3.14 gets bug fixes
  until October 2027 and security fixes until October 2030. 3.15, a month old, is too new for the
  wheels an image needs. The SBOM of a release's Python environment is resolved with the same
  interpreter, so the two SBOMs attached to a release describe one resolution;
  `tests/test_docker_python.py`, the same in every Radar, keeps them together. All six Radar are now
  built on 3.14. The test matrix (3.11 to 3.14) and the Python that runs the tools are unchanged.
  Measured on 2026-11-16: the image builds on 3.14.10, `--version` runs, pip is absent, and Trivy
  reports the same high findings as the published 3.12 image, all in Debian packages, none in
  Python.

- **The acl exception is reviewed, and runs to 2027-01-31.** CVE-2026-54369 was due on 2026-11-30,
  after which Security Posture would have failed on its own. Read again on 2026-11-17: still no-dsa
  for trixie (Debian bug 1141110), acl 2.4.0 only in forky and sid, nothing in
  trixie-proposed-updates, and the last point release still 13.7 of 2026-09-12. The new date falls
  after the 13.8 point release that is due.

### Fixed

- **Security Posture reads every page of alerts.** The code scanning API returns at most a hundred
  alerts per call, and the gate read one page of each list. Found in cookieradar on 2026-11-13
  (cookieradar #70): a pull request with 123 open alerts and main with 142, three exceptions whose
  findings sat past the hundredth read as matching nothing, and the gate failed on a product whose every
  alert was explained; read the other way, an unexplained alert past the hundredth would not have been
  seen at all. This repository had 55 open on main on 2026-11-15, so its gate had not met the limit yet.
  Each of the four reads now goes through `gh api --paginate --slurp` and joins the pages; a failed read
  still fails, so an unreadable list is not taken for an empty one.
  `tests/test_security_posture_workflow.py` runs the step's own function against a stand-in `gh` that
  answers in two pages.

- **A release no longer goes red because the index answered the check before it had caught up.** After
  the upload, *Publish to PyPI* installs the new version into a fresh venv to prove it installs.
  That was a single `pip install`, given no retry on the ground that the job has one resolver.
  apkradar 2026.48 disproved it on 2026-11-16: the wait saw the version at 15:04:30 and the install
  three seconds later, on the same runner, was told it did not exist, on a release that was fine.
  The install now goes through `.github/scripts/install_from_pypi.sh`, which asks again (ten
  attempts, 30 s apart) until it succeeds or names the version it could not install: the same
  script, and the same `tests/test_install_from_pypi.py`, in all six Radar. It installs the wheel
  only (`--only-binary :all:`), as apkradar and patchradar already did: the check is about the file
  that was uploaded, not a build of the sdist.

- **Security Posture gives no verdict on a failed Docker Scout scan.** It ran after every Scout run,
  failed ones included. On 2026-11-16 exeradar's Scout stopped on a 403 before scanning, and the
  gate went green on the previous scan's alerts. It now runs on a `workflow_run` only when the scan
  succeeded, as Scout itself does after the image workflow. Push, pull request, schedule and manual
  runs are unchanged.

- **Dependabot reads `uv.lock` for security updates.** patchradar's `uv.lock` held opentelemetry-api
  1.45.1 with a Dependabot alert on it from 2026-11-14, and no pull request came, because no entry
  of the configuration read `uv.lock`. A `uv` entry with `open-pull-requests-limit: 0` stops version
  updates for uv, so pip's remain the one weekly stream, and leaves security updates to arrive.

- **The README no longer says `--version` is unreleased.** It has shipped since 2026.09.9
  (2026-09-19), but the installation section still called it "not yet in a published release".
  `tests/test_version.py` now fails when a README paragraph calls unreleased something a dated
  CHANGELOG section already records.

- **Rebuilding the image by hand no longer offers September's release.** The `version` input of
  `docker.yml`'s manual run defaulted to `v2026.09.4`, so the form arrived pre-filled with a version
  that looked deliberate and would have republished it. It has no default now, as in apkradar;
  `tests/test_ci_scripts.py` keeps it that way.

- **The version typed into a manual image build is no longer pasted into the script.** `docker.yml`
  wrote `${{ github.event.inputs.version }}` straight into its `run:` block, so a value with a quote
  in it would have become shell code in a job that holds the Docker Hub token. It now arrives through
  `env:`, where it stays a string, as apkradar's did; a test refuses any workflow that pastes an input
  or event field into a script.

## [2026.47] - 2026-10-28

### Security

- **Every action in every workflow is pinned to a commit, with its release beside it.** Ten of the sixteen
  workflows named moving tags (`actions/setup-python@v7`, `actions/checkout@v7`, the Docker actions) and
  publish.yml, which holds the PyPI OIDC token, a branch: `pypa/gh-action-pypi-publish@release/v1`. Whoever
  moves a tag changes what these jobs run without a pull request here — `setup-python@v7` already ran
  7.1.0, released six days earlier. Each is now a full commit with `# vX.Y.Z`, the release its tag pointed
  to, or the one the other workflows already used where that was younger than two weeks; pypi-publish
  1.14.3 and scout-action 1.28.0 stay, being security releases. `tests/test_actions_pinned.py` holds all
  sixteen to it; tests/test_ci_contract.py held test.yml alone.

- **dnspython 2.9.0** in `uv.lock`, from 2.8.0. `dns.name.from_wire_parser()` before 2.9.0 can be made to
  use excessive CPU by a crafted name in a DNS message (GHSA-45c3-73f7-pv4m, CVE-2026-114605, high,
  published 2026-10-27); mailradar parses the answers of whatever resolver it is given. 2.9.0 is the
  release the advisory names as fixed, published 2026-10-09; the Security Posture gate stopped every
  pull request on Trivy's alert for it.

### Fixed

- **Docker Scout no longer fails on its own base-image advice.** From 2026-10-24 every run of
  `docker-scout.yml` failed and GitHub mailed it on each push to main: the CVE scan worked, then the scout
  CLI crashed in the `recommendations` part (nil pointer in `recommendations/markdown.go`) on images built
  on python:3.12-slim-trixie. The scan is now a step of its own that writes the SARIF and fails the job if it
  fails; the recommendations are a second step with `continue-on-error`. `tests/test_scout_steps.py`
  holds the two apart.
- **No score without a measurement.** When a DNS lookup got no answer (timeout, SERVFAIL), the
  checks were marked "not verified" but still counted 0 points, and `check` printed `0/100 CRITICAL`
  with exit code 2 — reported behind a company resolver for asufc.sanita.fvg.it, which scores 19 from outside.
  The analysis now has no score: `total_score` is `None`, the grade `N/A`, `check` names the checks
  that were not verified and exits with 3, and `batch` lists the domain as N/A after the graded ones.
  `DomainReport.unverified` names those checks. A keyserver that does not answer still leaves a score.

- **Docker Scout scans the image as soon as it is published, and Security Posture reads that scan.**
  The scan reads `latest` from Docker Hub but ran only on a push to main, weekly or by hand: after the
  2026.46 release the gate stayed red on the replaced image's old certifi until both were dispatched by
  hand. `docker-scout.yml` now follows the image workflow (`workflow_run`, successful runs only) and
  `security-posture.yml` follows the scan. `docs/nis2-compliance.md` already said the scan ran on every
  image build; now it does, and `tests/test_scan_after_publish.py` holds the two together.

## [2026.46] - 2026-10-23

### Security

- **certifi 2026.10.19** in `uv.lock` and `requirements-ci.txt`, from 2026.7.22. The older bundle trusts
  emSign root CAs whose intermediate CA keys were compromised (GHSA-6q48-6c7w-9gw2, critical, published
  2026-10-20); 2026.10.19 is the release the advisory names as fixed. The Security Posture gate stopped
  every pull request on it.

### Fixed

- **A missing DMARC record and MTA-STS now cite art. 24 of d.lgs. 138/2024, not art. 21 of the NIS2
  directive.** The directive binds the Member States; in Italy the duty of essential and important
  entities to take security measures is art. 24 of the decree that transposes it ("Obblighi in materia
  di misure di gestione dei rischi per la sicurezza informatica"), downloaded from Normattiva. The scope
  note now points to art. 3 of the decree.
- **A verified text names the source it came from.** EU acts are downloaded from Cellar
  (publications.europa.eu), with EUR-Lex only as the fallback, but the report said "verified against
  EUR-Lex" whichever answered. It now says Cellar, EUR-Lex or Normattiva, as the case was;
  `law_checker.check` takes an optional HTTP client, so the path can be tested on recorded answers.
- **`check` no longer turns a DNS failure into "domain not found", and no longer analyses
  somebody else's domain instead.** Reported by a user: `asufc.sanita.fvg.it` (Azienda sanitaria
  universitaria Friuli Centrale) came out as "not found in DNS", then as 0/100 with nothing
  configured. Three faults in a row:
  - `domain_exists` read any DNS error (a timeout over a slow resolver, a SERVFAIL) as "no such
    domain", and a name with no A record as missing too. It now asks for A once: NXDOMAIN is a
    missing name, NOERROR with no answer is a name that exists (`sanita.fvg.it` has MX and TXT,
    no A), and a lookup that gets no answer raises `DNSLookupError`. `check` then says the domain
    could not be checked and stops, exit code 1;
  - the variants scan kept only the first label, so `asufc.sanita.fvg.it` became `asufc.com` and
    `asufc.co.uk`. Variants are now tried only for a bare name or `name.tld`; a missing subdomain
    gets "check the domain name". A variant the DNS does not answer for is left out;
  - Enter alone at the variant prompt picked variant 1 and analysed it. The prompt has no default.

  Tests on DNS answers recorded from 1.1.1.1 on 2026-10-20, timeouts played by the local DNS
  server keeping silent; the two tests that patched `dns.resolver.resolve` are replaced by them.

## [2026.45] - 2026-10-17

### Added

- **`docs/nis2-compliance.md`: the answers to the seven questions a customer subject to NIS2
  asks a software supplier, with only what the repository can back.** Written in Italian, for
  customers under d.lgs. 138/2024. Where the answer is "no" it says no: there is no penetration
  test, no second reviewer and no access control, because a CLI has no users. It lists every
  host the tool contacts and what each one receives — the analysed domain to crt.sh and
  rdap.org, five role addresses of that domain to two keyservers, the cited acts to EUR-Lex and
  Normattiva — and `tests/test_nis2_evidence.py` compares that list with the hosts named in
  the modules that can reach the network, so the document goes red when the code changes.
  The same tests hold the image user, the cache path, the release files and the scanners to
  what the document says, and refuse "NIS2-ready", "no data sent to third parties" and
  similar claims anywhere in it, in `SECURITY.md` or in the README.
- **Every release carries SBOMs and dated scans** (`.github/workflows/sbom.yml`): CycloneDX 1.5
  of the image, Debian packages included (Syft), and of the Python environment
  (cyclonedx-py), plus Trivy reports of the image and of the repository at the tag, and a
  note saying which commit and image digest they describe and that a CVE scan is not a
  penetration test. It runs after the image of the tag has been pushed, and on demand for a
  release that is already out.
- **`SECURITY.md` says how vulnerabilities are found, how fast they are answered, how
  customers are told and how to roll back.** A fix ships with the next release; for CVSS 9.0
  or more, customers who gave a security contact hear within 48 hours. The paragraph on
  "Known Open CVEs", last reviewed on 2026-09-18, is gone: `SECURITY-EXCEPTIONS.toml` is
  where the accepted ones are, each with a review date.

### Fixed

- **`send` built a message a mail server could refuse, signed with placeholders.** In a dry run on
  2026-10-17 against a server on 127.0.0.1, the envelope said `MAIL FROM:<>` and the message had no
  `Date` and no `Message-ID`: `From` was written as `f"{name} <{address}>"`, smtplib took the
  envelope from it, and `[`/`]` are RFC 5322 specials — "[NOME] <a@b>" parsed to no address,
  "Rossi, Mario <a@b>" to "Rossi". `From` is now `formataddr`, `Date` and `Message-ID` are set, and
  the envelope sender is stated. With SMTP configured, `send` refuses to deliver "[NOME]",
  "[RUOLO]", "[ORGANIZZAZIONE]", before any network lookup.
- **A keyserver that did not answer let the report go out in plaintext.** Same dry run:
  keys.openpgp.org answered 429, the GPG check said "not verified", and the report was sent in
  clear. A key may exist where a keyserver did not answer, so `send` now sends nothing and exits 1;
  with every keyserver answering and no key, plaintext stays the documented fallback.
- **On a pull request, Security Posture called live exceptions unused.** CodeQL reports only what
  the change introduces on a pull request ref, so when it reported anything, an exception for a
  finding still open on main in an untouched file matched nothing and failed the gate
  (cookieradar #37, 2026-10-12). main's open alerts now count as history the record may match,
  like the closed ones; blocking is still decided on the pull request's own alerts. Simulated on
  #37's real alerts: the false "unused" goes, the real new alert stays.
- **Security Posture judged every pull request by main's alerts.** It listed the alerts without
  a `ref`, so GitHub answered for main, and its wait compared the scanners' runs with the merge
  commit, which none of them carries: on mailradar #39 it waited two seconds. It now waits for
  the runs of the branch head, Bandit included, and reads the open alerts of `refs/pull/N/merge`;
  the closed ones come from that ref and from main, so an exception main holds as settled is not
  called unused on a ref with no history. Checked against a recent pull request of each Radar
  with the real tool: the same verdict as main in all six.
- **The texts of the law arrived in clear.** Cellar answers its https:// URL with a 303 to an
  http:// one (recorded on 2026-10-11 for the GDPR), and `fetch_html` followed it, so the act
  travelled without TLS and the SHA-256 printed beside a citation described bytes nothing had
  protected. Redirects are now followed by hand and a hop to http:// is taken over https://,
  which serves the same document byte for byte; if that fails, the fallback to EUR-Lex applies.
  Checked live: the GDPR came back whole over two HTTPS requests. The test replays Cellar's
  recorded 303.
- **The release evidence describes what ships, and says when a scan saw nothing.** The
  source SBOM listed the build venv's own pip, which the image removes, and, the version
  being dynamic, named the package without a version: both are fixed, and a tag that
  disagrees with the installed version is refused. An empty `trivy-fs` report, as at a tag
  with no lockfile, is now called what it is in the note and in the document. CodSpeed is
  listed among the checks of question 5.
- **The document said every HTTP request named this repository in its User-Agent.**
  The BIMI, MTA-STS and keyserver requests, and two in `discover`, send httpx's default.
- **The Saturday mutation run would have died on the NIS2 tests.** mutmut copies only the
  paths in `also_copy` into `mutants/`, and `tests/test_nis2_evidence.py` reads `docs/`, which
  was not among them. Listed now, with a test that checks every file those tests read.
- **The licence gate had never refused anything.** `pip-licenses --fail-on="GPL;AGPL;LGPL"`
  compares whole licence strings, and no package declares just "GPL": they declare "GNU
  Lesser General Public License v2 or later (LGPLv2+)" and the like. Measured on 2026-10-11
  with chardet 5.2.0 installed: exit 0 without `--partial-match`, exit 1 with it. The flag is
  there now; MailRadar's own dependencies pass it.
- **`uv.lock` was three releases old.** `uv lock --check` refused it on 2026-10-11; it is
  regenerated, and the Quality workflow now fails when it falls behind `pyproject.toml`.

### Changed

- **`SECURITY-EXCEPTIONS.toml`: the settled entries that stay now say why.** Snyk stopped reporting
  the gcc-14 advisories on 2026-10-07 and 2026-10-08, and Docker Scout, which had lost and regained
  CVE-2026-102010 and CVE-2026-95619 once, last closed them on 2026-10-12, so the gate lists all four
  entries as settled. `patchradar debian` on 2026-10-15
  still reports gcc-14 no-dsa in trixie at 14.2.0-19, with the fix only in sid, so the package is
  still unfixed and only the reporting changed. The same holds for CVE-2026-82560 in perl, quiet
  since 2026-10-05 and still no-dsa with no fix in any suite (Debian bug 1148455). The entries are
  kept, and each now records when the scanner fell silent and what Debian said, as the
  CVE-2026-82560 entry in the other Radar already did. Deleting a flaw that is demonstrably present
  because a scanner fell silent is the one direction the file must not drift in.

- **The NIS2 document describes the branch rules as they are since 2026-10-12.** The ruleset on
  main lost the owner's bypass and requires a pull request for every change, the version bump
  included; the document said the maintainer could bypass the rules. A test holds the new
  wording and refuses the old.
- **`release.sh` falls back to a rebase merge** when the ruleset refuses a squash, as apkradar's
  does, and says to enable auto-merge when it cannot be turned on.
- **`release.sh` goes through a pull request.** main now takes pull requests only, the owner
  included, after a cloud session pushed straight to it with the owner's account. The script
  commits the bump on `release/vX` and pushes that branch only; with `gh` and a GitHub origin it
  opens the pull request with auto-merge, waits for the merge and tags the merge commit.
  `./release.sh --tag X` is that last step alone. The guarantees stay: nothing is committed when
  the suite fails, and the tag is made before anything is pushed.

### Removed

- **CVE-2026-84782 (openssl) and CVE-2026-103111 (pcre2) out of `SECURITY-EXCEPTIONS.toml`.** Both
  entries described a rebuild rather than an acceptance. Debian fixed both in trixie (openssl
  3.5.7-1~deb13u3, pcre2 10.46-1~deb13u3), GitHub closed both alerts on 2026-10-04, and the
  scheduled no-cache rebuild of 2026-10-12 did not bring them back. If either returns, a fix has
  regressed, and that is worth a failing build.

## [2026.44] - 2026-10-10

### Fixed

- **A GPG key is credited only when the keyserver verified the address, and a keyserver that
  does not answer is not "no key".** Run on ten real domains on 2026-10-09, `check` showed
  "GPG ✅" for gmail.com, poste.it, polimi.it, github.com and pec.poste.it — none of which
  publishes a key for its role addresses. Three causes, all in `mailradar.gpg`:

  - the HKP lookup asked `op=get&search=<address>`, and SKS-type servers search by
    substring or by word: keyserver.ubuntu.com answered `security@gmail.com` with four keys,
    among them `eli.geminder+security@gmail.com` and one uploaded in 2018 by
    "securityencyryption", and pgp.mit.edu answered `postmaster@pec.poste.it` with the key of
    a private person none of whose 72 uids carries the address or the domain (recorded in
    `tests/fixtures/http/pgp_mit_edu_pec_poste_it.json`). `send` would have encrypted the
    report to that key. The lookup now asks `op=index` first and takes a key only when one of
    its uids is exactly the address and the key is not revoked, disabled or expired;
  - every key counted 5 points, although only keys.openpgp.org publishes an address after
    its owner answered a verification mail. A key from keyserver.ubuntu.com is now reported
    with its fingerprint and "address not verified", scores 0, and the law check does not
    change over it; `found` stays True, so `send` behaves as before;
  - an HTTP 429 or a timeout was read as "no key". keys.openpgp.org allows one by-email
    lookup a minute with a burst of 50, and `check` made two requests per address against
    it (VKS, then the HKP interface of the same host for the same answer): after a few
    domains every lookup was a 429, the table said "No public key on keyservers" and the
    report cited GDPR art. 32 for "GPG not available". A keyserver that does not answer is
    now asked nothing more during the analysis, and if the key was not found elsewhere the
    row says "Not verified: keyserver did not answer", `GPGResult.error` carries the reason
    and `law_checker` cites nothing for it. keys.openpgp.org is asked once per address.

  pgp.mit.edu is no longer a default keyserver. That day it took the full 15 s to time out
  on each of the five contact addresses — 83 s of an 86 s analysis of github.com, poste.it
  and unicredit.it — answered HTTP 500 at other moments, and the one time it answered in
  0.6 s it returned the wrong key above. Between two runs an hour apart the score of
  github.com moved from 46 to 51, poste.it from 28 to 32 and polimi.it from 49 to 54 on its
  answers alone.

  The cases replay the answers recorded that day on 127.0.0.1: keyserver.ubuntu.com's index
  and key for security@gmail.com, the five 429s for github.com, security@mozilla.org as a
  verified key on keys.openpgp.org, pgp.mit.edu's wrong key and its timeouts.

- **DKIM asks for every common selector, 33 of them, and measures the weakest key found.**
  `check proton.me` said "No DKIM record found with common selectors" and the law check cited
  GDPR art. 32 for "no DKIM key under the common selectors": proton.me signs under
  `protonmail` and `protonmail2`, two 2048-bit keys, and none of the 17 selectors tried was
  one of them. The list gains Proton's three, Fastmail's `fm1`-`fm3`, `amazonses`,
  `zendesk1`/`zendesk2`, `k2`, `k3`, `pm`, `cm`, `dkim1`, `dkim2` and `smtp`.

  The check used to stop at the first selector with a key. inps.it and polimi.it, both on
  Microsoft 365, publish a 1024-bit key under `selector1` and a 2048-bit one under
  `selector2`: the table showed the first and said "upgrade to 2048-bit" about a domain that
  has the 2048-bit key already. Every selector is now asked for; a receiver verifies a
  signature made with any published key, so the weakest one is the posture and sets the
  score, and `DKIMResult.keys` names them all — the table shows `selector1: 1024-bit RSA |
  selector2: 2048-bit RSA`, the issue says which is weak and what else is there. On the
  recorded startpage.com this finds a 1024-bit SendGrid key under `s2` beside the 2048-bit
  `google` one, and the domain's score goes from 79 to 74.

  A key under none of the 33 is "not found", never absent: DNS cannot list selectors, and
  amazon.it (recorded) signs under selectors of its own. The issue now reads "No DKIM key
  found under 33 common selectors — a custom selector cannot be ruled out: check the s= tag
  of a received message's DKIM-Signature header", and the row "Not found under 33 common
  selectors". The cases replay proton.me, polimi.it, amazon.it, inps.it and startpage.com as
  recorded from 1.1.1.1 on 2026-10-09. Asking 33 selectors instead of stopping at the first costs
  DNS round trips, not CPU: the key parse is cached by record, since the same key is often
  published under several selectors.

- **The law check no longer cites GDPR art. 32 for a DKIM key it did not find.** "no DKIM key
  under the common selectors" was evidence for the "SPF/DKIM weak" finding, and the report to
  the domain's owner cited the article over it: for proton.me, whose keys exist under other
  selectors, and for amazon.it, unicredit.it and poste.it, which sign under selectors of their
  own. Not measured is not zero. A key that was found and is shorter than 2048 bits is still
  cited; a key not found under the 33 selectors is reported in the table and the issues, and
  nothing is cited for it. The case replays amazon.it as recorded on 2026-10-09.

- **The letter `report` writes says what was found, without the empty lines.** Generated for
  inps.it, which publishes `p=reject`, it told the owner that "anyone can send emails
  impersonating @inps.it": the GDPR paragraph about a missing or `p=none` DMARC was
  unconditional. It is now written for `p=none` or no record, a `p=quarantine` domain gets
  a sentence about what quarantine does not do, and a `p=reject` domain gets neither. DKIM
  "Current: Not configured" was written for every domain without a key under the common
  selectors — amazon.it, unicredit.it, poste.it, all of which sign — and for a revoked key:
  the letter now writes every key found (`Keys found: selector1 1024-bit RSA, selector2
  2048-bit RSA`), the revocation, or "No key under 33 common selectors — a custom selector
  cannot be ruled out", and the recommendation for the last case is a key under the
  selector in use, not a new selector. The Jinja environment trims block lines
  (`trim_blocks`, `lstrip_blocks`): the sections were separated by two to five empty lines.
  Both languages; the cases replay inps.it, pec.poste.it and amazon.it as recorded.

- **The Details column cuts with an ellipsis, shows a TLS-RPT address whole when it fits, and
  the SPF verdict names the redirect it comes from.** github.com's 330-character SPF record
  ended in `include:spf.protection.outlo` with nothing to say it was cut; proton.me's TLS-RPT
  address `https://reports.proton.me/reports/smtptls` lost its last letter to a 40-character
  cut inside a 55-column cell; and gmail.com's issue read "SPF uses ~all" under a record that
  shows only `redirect=_spf.google.com` — it now reads "SPF uses ~all (softfail) via
  redirect=_spf.google.com". The cases replay github.com, proton.me and gmail.com as recorded.


## [2026.43.1] - 2026-10-09

### Changed

- **Python 3.14 is a stable row of the test matrix and 3.15-dev is the experimental one.**
  pyproject has declared 3.14 since the suite started running on it, and `test.yml` still
  listed it as the `-dev` row that is allowed to fail: a version promised on PyPI could not
  redden the build. 3.15.0 is final on 2026-10-09 (PEP 790) and `actions/setup-python`
  already resolves `3.15-dev` to rc.3, so the experimental row moves there, as in patchradar.
  Two tests now hold the matrix to the classifiers: every declared version is stable in
  CI, and the one `-dev` row is the minor after the last stable one. 3.15 enters the
  classifiers when it is final, not before.

### Security

- **The image installs `gpg` and `gpg-agent`, not the `gnupg` metapackage.** Security
  Posture on `main` was red for Docker Scout alert #66: CVE-2026-107161, high, in cyrus-sasl2
  (`libsasl2-2`), with no fix in trixie and nothing to wait for. The library was there for
  one reason: `gnupg` is a metapackage, and it pulls in `dirmngr`, which depends on
  `libldap2`, which depends on `libsasl2-2`. dirmngr is gpg's keyserver and WKD client, and
  nothing in mailradar uses it — `sender.py` runs gpg for `--import`, `--encrypt
  --trust-model always` and `--clearsign --pinentry-mode loopback`, and the public key it
  imports has already been fetched over HTTP by `mailradar.gpg`. No `--recv-keys`, no
  keyserver, no WKD.

  Measured in `python:3.12-slim-trixie`: `gnupg` brings 21 packages, `gpg gpg-agent` 9,
  none of them libsasl2, libldap or dirmngr. The image goes from 108 installed packages to
  96 and loses 12.7 MB; `docker scout cves --only-package cyrus-sasl2` finds the one high
  on the old image and no package at all on the new one. The three gpg calls were run for
  real in the new image, offline, on a key generated there — generate, export, import into
  an empty homedir, encrypt, clearsign, verify — and `sender._encrypt_with_gpg` and
  `sender._sign_with_gpg` themselves were called in it the same way.

  Two cases hold it: `tests/test_docker_contract.py` parses the Dockerfile's `apt-get
  install` and requires exactly `gpg` and `gpg-agent`, and `tests/docker/inspect.sh`, run
  on the built image by `docker-build-check.yml`, asks dpkg that `libsasl2-2`, `dirmngr`
  and `gnupg` are absent and `gpg` and `gpg-agent` present, then runs the flow above and
  fails the step if any of it does not hold. Until this change inspect.sh only reported;
  that section judges, because a one-word edit would reopen the finding without anything
  else in the build changing.


## [2026.43] - 2026-10-08

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
  raised no issue at all, `mode: none` (valid, RFC 8461) was "mode unknown", and the report
  for the owner said "Current: Not configured" for a policy in testing mode.

- **Smaller fixes.** `check example.com.` treated the trailing dot as a missing domain,
  and `analyze_domain` now normalises the name once, so GPG and MTA-STS no longer see
  `Example.COM.`. RDAP addresses are matched on the domain, not as a substring
  (`admin@example.com.evil.org`); the SOA contact is matched case-insensitively and a TXT
  record that is not UTF-8 no longer hides the others. `python -m mailradar.cli` ran the
  app before `report`, `send` and `discover` were defined. `batch` crashed with a Rich
  `MarkupError` on a file name containing `[`.

- **Repository.** `.gitattributes` checks the `.sh` scripts out with LF, without which
  `core.autocrlf=true` broke `release.sh` on `set -o pipefail`. A bare `pytest` no
  longer collects the benchmarks, whose runner the dev extra does not install. The
  Changelog URL in `pyproject.toml` answered 404, Python 3.14 is listed among the
  classifiers, and in the image the working directory is the volume, so `report --save`
  no longer writes its file where `docker run --rm` throws it away.

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

[Unreleased]: https://github.com/maksimtech/mailradar/compare/v2026.48...HEAD
[2026.48]: https://github.com/maksimtech/mailradar/compare/v2026.47.1...v2026.48
[2026.47.1]: https://github.com/maksimtech/mailradar/compare/v2026.47...v2026.47.1
[2026.47]: https://github.com/maksimtech/mailradar/compare/v2026.46...v2026.47
[2026.46]: https://github.com/maksimtech/mailradar/compare/v2026.45...v2026.46
[2026.45]: https://github.com/maksimtech/mailradar/compare/v2026.44...v2026.45
[2026.44]: https://github.com/maksimtech/mailradar/compare/v2026.43.1...v2026.44
[2026.43.1]: https://github.com/maksimtech/mailradar/compare/v2026.43...v2026.43.1
[2026.43]: https://github.com/maksimtech/mailradar/compare/v2026.42...v2026.43
[2026.42]: https://github.com/maksimtech/mailradar/compare/v2026.41...v2026.42
[2026.41]: https://github.com/maksimtech/mailradar/compare/v2026.40...v2026.41
[2026.40]: https://github.com/maksimtech/mailradar/compare/v2026.09.12...v2026.40
[2026.09.12]: https://github.com/maksimtech/mailradar/compare/v2026.09.11...v2026.09.12
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
