# Säkerhetsgranskning av pretest — rond 6

Verifieringen kördes lokalt med syntetiska markörer och localhost-fixtures. Inga kundsystem eller kundcredentials användes. Nya fel bedöms endast i `git diff d6d0ad3..HEAD -- pretest.py`.

## Rond 5: blockerare

| blockerare från rond 5 | åtgärdad? | kommandot som visar det |
|---|---|---|
| URL-userinfo skrivs rått till CLI:ns stderr | ja | `python3 pretest.py --url "http://fixture-user:URL_SECRET_FIXTURE_987654@127.0.0.1:$PORT" --no-portscan --no-dns --delay 0 --json "$TMP/out.json"` (kört med syntetisk userinfo och localhost). Markören saknades i stdout, stderr och JSON; stderr visade `mot http://…@127.0.0.1:$PORT`, JSON `target` var `http://…@127.0.0.1:$PORT`. Körningen rapporterade `Ingen HTTP-anslutning`: urllib anslöt inte med userinfo-URL:en. |
| Rond 5 återbekräftade också att userinfo maskeras i rapportens text- och JSON-`target` | ja | Samma kommando ovan; markören saknades i båda kanalerna och JSON-target var maskerad. |

## Fyrkälligt hemlighetsprov

Kört CLI mot lokal HTTP-fixture med normal URL och syntetiska markörer i `.env` (`API_SECRET`), `Set-Cookie`, en intressant HTML-kommentar och en 500-sidas Python-traceback. Kommandot hade `--no-portscan --no-dns --delay 0 --json "$TMP/report.json"`.

| Källa | Upptäckt i text/JSON | Hemlighet läckte i text | Hemlighet läckte i JSON |
|---|---|---:|---:|
| `.env` (`API_SECRET`) | `exposed-.env` | nej | nej |
| `Set-Cookie` | `cookie-flags-session` | nej | nej |
| HTML-kommentar | `html-comments` | nej | nej |
| Python-traceback | `error-leak-python-traceback` | nej | nej |

Kontrollen läste faktisk stdout och den skrivna JSON-filen och sökte efter respektive unika syntetiska markör. Alla fyra fynd fanns i båda rapporterna; ingen av markörerna fanns där.

## Nya fel i diffen

Granskad diff: `git diff d6d0ad3..HEAD -- pretest.py` (60 tillagda och 39 borttagna rader). Inga nya säkerhetsfel som når blockerartröskeln visades av motproven. Den nya HTTPS-entry-kontrollen kördes mot den självsignerade TLS-fixturen i `python3 pretest.py --self-test` och producerade `https-cert-broken` med hög allvarlighet. Samma kommando slutade med `OK` (22 förväntade fynd, 0 falska larm, TLS-kontroll prövad). `git diff --check d6d0ad3..HEAD -- pretest.py` gav inga whitespacefel.

## DOM: WOW
