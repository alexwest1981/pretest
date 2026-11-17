# Korrekthetsgranskning av `pretest.py` — rond 5

Jag läste rond 4, aktuell `pretest.py` och `git diff 4719d83..HEAD -- pretest.py`. Jag körde DNS-, JS-, HTTPS- och origin-motprov med både felande och friska svar samt självtestet.

## Rond 4-blockerare

| Rond 4-blockerare | Åtgärdad? | Kommando som visar det |
|---|---|---|
| Misslyckat A-uppslag för en intressant subdomän tystas. | Ja. Ett tomt CNAME-svar följt av A-timeout ger `dns-unavailable-subs`; frisk tom DNS ger inte oprövat-fyndet. | DNS-heredocen under **Körda motprov** (`dns subdomain A timeout` och `dns healthy empty subdomain`). |
| HTTPS-fel kan bli `no-https` high när HTTP svarar på alternativ port eller HTTPS-nätet är otillgängligt; proben använder dessutom `urlsplit(url).netloc`. | Nej. Timeout blir informativt `https-unreachable`, men känt `Connection refused` ger fortfarande `no-https` high. I motprovet används `http://example.com:8080`, medan HTTPS-proben bygger `https://example.com:8080/`; fyndet säger ändå att HTTPS inte fungerar. | HTTPS-delen i heredocen under **Körda motprov**. `sed -n '162,190p' pretest.py` visar även att HTTPS-proben använder `netloc` och att `reason` leder direkt till `no-https`. |
| JS-bundlefel ger både `js-partial` och det missvisande `js-none` (“0 externa …”). | Nej. Ett misslyckat externt bundle ger fortfarande båda fynden. | JS-delen i heredocen under **Körda motprov**; `sed -n '468,491p' pretest.py` visar att `js-none` läggs till när inga bodies hämtats, trots att `srcs` innehåller misslyckade hämtningar. |
| Ogiltig port skiljs inte från utelämnad standardport i origin-kontrollen. | Nej. `ValueError` fångas och porten blir standardporten. | `python3 - <<'PY'`-motprovet under **Körda motprov** visar att `https://example.com:notaport/` och `https://example.com/` båda blir `('https', 'example.com', 443)`; `sed -n '101,111p' pretest.py` visar orsaken. |

## Körda motprov

DNS subdomänens A-timeout och frisk kontroll:

```text
$ python3 - <<'PY'
# Heredoc skapar friska basposter, svarar None enbart på vald fråga,
# returnerar admin.example.com från _crtsh och skriver ut FINDINGS.
# Fullt kommando kan återskapas från motprovet i rond 4 med fail=('admin.example.com','A').
PY
```

Utskrift från det körda motprovet:

```text
dns subdomain A timeout: ['dkim-unknown', 'dns-unavailable-subs', 'no-caa']
dns healthy empty subdomain: ['dkim-unknown', 'no-caa']
```

JS- och HTTPS-provet kördes i samma Python-heredoc. JS hämtade en sida med `<script src="/app.js">`, och `fetch` stubbas först till timeout och sedan HTTP 200. HTTPS-testet gav HTTP 200 för `http://example.com:8080/` och testade timeout respektive `Connection refused` på den konstruerade HTTPS-adressen.

```text
JS bundle timeout: [('js-partial', '1 skript kunde inte hämtas'), ('js-none', 'Inga skript att genomsöka')]
JS bundle healthy: []
HTTPS timeout: [('https-unreachable', 'HTTPS nåddes inte — orsaken är okänd')]
HTTPS connection refused: [('no-https', 'HTTPS fungerar inte: anslutningen nekades')]
```

Origin-motprov:

```text
$ python3 - <<'PY'
import pretest
for url in ['https://example.com:notaport/','https://example.com:0/','https://example.com/']:
    try: print(url, '=>', pretest._origin(url))
    except Exception as e: print(url, '=> raises', type(e).__name__, str(e))
PY
```

```text
https://example.com:notaport/ => ('https', 'example.com', 443)
https://example.com:0/ => ('https', 'example.com', 0)
https://example.com/ => ('https', 'example.com', 443)
```

Självtest och whitespace-kontroll:

```text
$ python3 pretest.py --self-test
self-test: 22 förväntade fynd, 0 falska larm på ren fixture, TLS-kontroll prövad
OK
$ git diff --check 4719d83..HEAD -- pretest.py
# ingen utskrift
```

## Nya blockerare i ändringarna sedan `4719d83`

Ändringarna i diffen rör versionsnummer, redigering av fyndens ID/area och rapportmål, JWT-severitet/evidens, A-uppslag för subdomäner samt redigeringskontroller i självtestet. A-ändringen klarade motprovet ovan. `python3 pretest.py --self-test` täcker också att den opaka hemligheten inte läcker via JSON-ID/area eller rapportens target. Jag hittade inget nytt blockerande fel i ändringarna som kunde styrkas med ett kört motprov.

## Bedömning

Den tidigare tysta subdomänens A-timeout är åtgärdad, och vanlig HTTPS-timeout klassas som oprövad. Jag skulle ändå inte stå för en produktionsrapport: motprov visar fortfarande missvisande `js-none` vid bundle-timeout och ett high `no-https` för `Connection refused` i alternativportsfallet. Origin-kontrollens ogiltiga port kollapsar dessutom till standardport, vilket kan ge fel credential-originbeslut.

## DOM: INTE WOW — JS-timeout redovisas fortfarande som inga script, HTTPS-avvisning på alternativ port blir ett high-fynd och ogiltig port likställs med standardport.
