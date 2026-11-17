# Rond 6 — verifiering

## Rond 5-blockerare

| Blockerare från rond 5 | åtgärdad? | kommandot som visar det |
|---|---|---|
| Self-testet kunde missa att TLS-kontrollen tas bort ur `scan()`. | ja | `python3 /tmp/pretest-r6/drop-tls.py --self-test` → exit 1; rapporterar att självsignerat certifikat inte fångades och att TLS-kontrollen inte kördes. |
| Self-testet accepterade `jwt-weak-secret` med severity `low`. | ja | `python3 /tmp/pretest-r6/jwt-low.py --self-test` → exit 1; `FEL: jwt-weak-secret: low != high`. |

## Begärda motprov

Mutationerna gjordes i separata kopior under `/tmp/pretest-r6/`; `pretest.py` lämnades orörd.

```text
$ python3 pretest.py --self-test
self-test: 22 förväntade fynd, 0 falska larm på ren fixture, TLS-kontroll prövad
OK

$ python3 /tmp/pretest-r6/drop-tls.py --self-test
FEL: TLS-kontrollen fångade inte ett självsignerat certifikat
FEL: TLS-kontrollen kördes inte alls (ingen tls-post)
exit=1

$ python3 /tmp/pretest-r6/jwt-low.py --self-test
FEL: jwt-weak-secret: low != high
exit=1

$ python3 /tmp/pretest-r6/redact-bypass.py --self-test
FEL: _redact lämnade kvar 'hunter2'
FEL: _redact lämnade kvar 'pretestsentinelvalue123456'
FEL: _redact lämnade kvar 'u:p@'
FEL: _redact lämnade en hemlighet i fälten: evidence, why, fix
FEL: _redact lämnade en hemlighet i id/area
FEL: _redact lämnade URL-userinfo i target
exit=1
```

Samtliga tre efterfrågade regressioner fälls av self-testet.

## Nya fel i `git diff d6d0ad3..HEAD -- pretest.py`

Inga nya blockerare påvisade i den avgränsade diffen. Den innehåller bland annat ändringen till JWT-severityassertionen, TLS-test av `scan()` och redigering av rapportens target. Motproven ovan bekräftar att JWT-assertionen och TLS-assertionen fungerar; redaction-motprovet visar att `_redact` inte kan kringgås genom den begärda kortslutningen.

## DOM: WOW
