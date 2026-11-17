# Rond 5 — avgörandet

Läste rond 4 och aktuell `pretest.py`. Körningarna gjordes mot arbetskopian eller temporära mutationer i `/tmp/pretest-r5/`; ingen muterad fil ersatte `pretest.py`.

## Rond 4-blockerare

| Blockerare från rond 4 | åtgärdad? | kommandot som visar det |
|---|---|---|
| Self-testet accepterade att TLS-kontrollen tas bort ur `scan()`. | ja | `python3 /tmp/pretest-r5/drop_tls_scan_call.py --self-test` → exit 1; `FEL: TLS-kontrollen fångade inte ett självsignerat certifikat` och `FEL: TLS-kontrollen kördes inte alls (ingen tls-post)`. Mutationen tar bort TLS-fixturets `scan(...)`-anrop. |

## Baslinje och motprov

```text
$ python3 pretest.py --self-test
self-test: 22 förväntade fynd, 0 falska larm på ren fixture, TLS-kontroll prövad
OK

$ python3 /tmp/pretest-r5/drop_tls_scan_call.py --self-test
... FEL: TLS-kontrollen fångade inte ett självsignerat certifikat
... FEL: TLS-kontrollen kördes inte alls (ingen tls-post)
exit=1

$ python3 /tmp/pretest-r5/drop_nosniff.py --self-test
... FEL: saknas: no-nosniff
exit=1

$ python3 /tmp/pretest-r5/identity_redact.py --self-test
... FEL: _redact lämnade en hemlighet i id/area
... FEL: _redact lämnade URL-userinfo i target
exit=1

$ python3 /tmp/pretest-r5/report_target_raw.py --self-test
... FEL: _redact lämnade URL-userinfo i target
exit=1
```

Tre eller fler oberoende mutationer fälls; bland dem den uttryckligen begärda borttagningen av TLS-anropet ur `scan()`.

## Nya blockerare i ändringen

Granskad diff: `git diff 4719d83..HEAD -- pretest.py`. Den ändrar versionsnumret, redigerar fynd-ID/area och rapportens target, justerar JWT-svag-hemlighetens allvarlighetsgrad och ändrar hantering av oprövade DNS-svar.

JWT-ändringen saknar severity-regressionstest. I en kopia ändrades `jwt-weak-secret` från `high` till `low`, och det befintliga self-testet accepterade rapporten:

```text
$ python3 /tmp/pretest-r5/wrong-jwt-severity.py --self-test
self-test: 22 förväntade fynd, 0 falska larm på ren fixture, TLS-kontroll prövad
OK
exit=0
```

Detta är en blockerare för den angivna användningen: ett matematiskt verifierat fynd om en gissningsbar JWT-signeringshemlighet kan då rapporteras som `low` utan att self-testet märker det. Rapportens text säger att backendens acceptans inte är prövad, men det förklarar inte bort att en allvarlighetsgrad som gör fyndet lätt att förbise passerar oförändrat. Rondens diff visar själva ändringen `critical` → `high`, medan självtestets severityassertioner inte omfattar `jwt-weak-secret`.

Övriga granskade diffdelar gav inga nya blockerare i de körda motproven. Redigering av ID/area och URL-target fälls när deras redigering tas bort; DNS-ändringen märker saknat DoH-svar som oprövat.

## DOM: INTE WOW — self-testet accepterar att verifierat jwt-weak-secret-fynd nedgraderas till low.
