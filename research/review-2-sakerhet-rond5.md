# Säkerhetsgranskning av pretest — rond 5

Avgöranderond. Motproven kördes mot lokal HTTP-fixture med syntetiska värden; inget kundmål eller kundcredential användes.

## Rond 4: blockerare

| blockerare från rond 4 | åtgärdad? | kommandot som visar det |
|---|---|---|
| URL-userinfo skrivs osanerat ut i `target` i text- och JSON-rapport | ja, i själva rapporterna | `python3 pretest.py --url "http://fixture-user:URL_SECRET_FIXTURE_987654@127.0.0.1:$PORT" --no-portscan --no-dns --delay 0 --json "$TMP/out.json"` gav `Mål: http://…@127.0.0.1:$PORT`, JSON `target` lika sanerad, och markören saknades i båda rapporterna. Körningen når inte fixturen med userinfo i URL:en, men rapporten innehåller ändå målsträngen. Se ny blockerare nedan: CLI-diagnostiken skriver den råa URL:en till stderr. |

## Fyrkälligt hemlighetsprov

Kommandot kördes mot lokal fixture med `--url http://127.0.0.1:$PORT --no-portscan --no-dns --delay 0 --json "$TMP/out.json"`. Fixturen exponerade syntetiska värden i hemlighetslik miljövariabeltext, `Set-Cookie`, HTML-kommentar och Python-traceback. Alla fyra upptäcktes i relevanta fynd men inget hemlighetsvärde fanns i text- eller JSON-rapporten:

| källa | textläcka | JSON-läcka |
|---|---:|---:|
| env (`API_SECRET=…`) | nej | nej |
| cookie | nej | nej |
| opak HTML-kommentar | nej | nej |
| opak traceback/feltext | nej | nej |

Körningen gav fynden `cookie-flags-session`, `error-leak-python-traceback` och `html-comments`, bland övriga fixture-fynd. Den fyrkälliga kontrollen är därmed meningsfullt körd mot skannerns text- och JSON-utdata.

## Nya blockerare i ändringarna

Granskad diff: `git diff 4719d83..HEAD -- pretest.py`.

### Userinfo läcker fortfarande från CLI

`main()` skriver `base` rått till stderr före skanningen. Motprov: samma lokala fixture och

```sh
python3 pretest.py --url "http://fixture-user:URL_SECRET_FIXTURE_987654@127.0.0.1:$PORT" --no-portscan --no-dns --delay 0 --json "$TMP/out.json"
```

gav stderr-raden:

```text
# pretest 1.2.1 mot http://fixture-user:URL_SECRET_FIXTURE_987654@127.0.0.1:$PORT — endast mot system du äger eller har tillstånd att testa
```

Credentialen finns alltså kvar i den vanliga CLI-körningens diagnostikutdata. Att rapportobjektet sanerar `target` löser inte läckan i stderr. Det blockerar användning med kundens credentials och kundens produktion med rapportansvar.

Diffens övriga ändringar gav ingen ytterligare blockerare i denna granskning. `_redact` för ID/area och userinfo i rapportens target klarade de körda proven; JWT-fyndets nedtonade påstående är försiktigare; DNS-ändringen markerar DoH-fel som overifierade. Fyrkällsprovet och `python3 pretest.py --self-test` (22 förväntade fynd, 0 falska larm, TLS-kontroll prövad; `OK`) passerade.

## DOM: INTE WOW — CLI skriver URL-userinfo osanerat till stderr.
