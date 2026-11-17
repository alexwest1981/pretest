# Granskning av fyndkvalitet — rond 5

Jag läste rond 4, gick igenom hela `pretest.py` och granskade `git diff 4719d83..HEAD -- pretest.py`. Jag körde självtestet och motprov mot den ändrade JWT-fyndvägen och rapportens redigering. Domen gäller att köra verktyget med kundens credentials mot kundens produktion och stå för rapporten.

## Rond 4: blockerare

| Blockerare från rond 4 | Åtgärdad? | Kommandot som visar det |
|---|---|---|
| JWT-kandidatnyckelmatchning gav `critical` och påstod verifierad kontokapning, fast backendacceptans inte testats. | Ja. Fyndet är `high`; rubrik och varför-text uppger uttryckligen att acceptansen inte prövats och beskriver kontokapning som villkorad. | `python3 - <<'PY'` med `pretest._fixture_hs256('secret')`, `pretest.jwt_checks(...)` och utskrift av `FINDINGS['jwt-weak-secret']` visar `sev: high` och den villkorade formuleringen. Samma kommando skriver JSON-rapportens fyndpost. |

## Motprov

Självtest:

```text
$ python3 pretest.py --self-test
self-test: 22 förväntade fynd, 0 falska larm på ren fixture, TLS-kontroll prövad
OK
```

JWT-motprov med en token signerad med fixture-nyckeln `secret`:

```text
JWT finding: {"id": "jwt-weak-secret", "sev": "high", ...,
 "title": "JWT signerad med en gissningsbar hemlighet (backendens acceptans är inte prövad)",
 "evidence": "signaturen matchar en nyckel ur en kort gissningslista ('s…t', 6 tecken) — matematiskt verifierat",
 "why": "Signaturen går att återskapa med en nyckel från en kort lista. Om backend accepterar en sådan token kan alla konton kapas — det prövar verktyget inte."}
```

Detta är samma fyndskapande väg som körningen använder. Den redaktionella rapportposten och JSON-posten har samma `high`-nivå och begränsning. Motprovet provar ingen kundserver och hävdar inte att den gör det.

Redigeringsmotprov för de nya serialiseringsvägarna:

```text
redacted key: ['bad-url?secret=…']
opaque in findings: False
opaque in target JSON: False
```

En opak sentinel lades i fyndets id/area och i URL-userinfo för rapportmålet; ingen av rapportvägarna lämnade ut den. `python3 -m py_compile pretest.py` avslutades utan fel.

## Nya blockerare i ändringarna

Diffen ändrar versionssträng, redigering av fyndfält/rapportmål, JWT-klassning och DNS-subdomäners verifieringsräkning. Motproven ovan visar att JWT-påståendet nu är proportionerligt och att sentinelvärdet maskeras i de nya serialiserade fälten. DNS-ändringen räknar uteblivet A/CNAME-svar som oprövat och rapporterar det som info; jag fann inget nytt blockerande fynd där. Inget kört motprov visade en ny blockerare.

## DOM

## DOM: WOW
