# Korrekthetsgranskning av `pretest.py` — rond 6

Jag läste rond 5, aktuell `pretest.py` och körde motprov över JS-, HTTPS- och TCP-portvägarna. Jag granskade nya fel endast i `git diff d6d0ad3..HEAD -- pretest.py`.

## Rond 5-blockerare

| Rond 5-blockerare | Åtgärdad? | Kommandot som visar det |
|---|---|---|
| Misslyckad JS-bundle gav både `js-partial` och det missvisande `js-none`. | Ja. När enda externa bundle misslyckas blir det bara `js-partial`; frisk bundle ger inget fynd. | Python-heredocen under **Körda motprov**, JS slow/healthy. |
| HTTPS-proben för alternativ HTTP-port var missvisande, och nät-timeout kunde inte skiljas från saknad HTTPS. | Ja. HTTP på port 8080 utlöser `https-standard-port-unchecked`; HTTPS-timeout på standardporten blir `https-unreachable`/info. Trasigt certifikat har separat fynd. | `sed -n '147,205p' pretest.py`; heredocen under **Körda motprov**, HTTPS slow/dead/healthy. |
| Ogiltig port ekvivalerades med standardport i origin-kontrollen. | Ja. `_origin` låter `urlsplit().port`-felet bubbla upp; `fetch` avvisar auth vid `ValueError`, och `scan` avvisar URL:en. | `sed -n '102,126p' pretest.py`; `https://example.com:notaport/`-rad i Python-heredocen under **Körda motprov**. |

## Körda motprov

Kommando för JS-, HTTPS-, port- och ogiltig-port-vägar:

```sh
python3 - <<'PY'
import pretest, socket
page={'url':'http://slow.test/','text':'<script src="/app.js"></script>'}
orig=pretest.fetch
for label, response in [('slow',(None,None,b'TimeoutError()')),('healthy',(200,{},b'var x=1;'))]:
    pretest.FINDINGS.clear()
    pretest.fetch=lambda url, **kw: (200,{},b'') if url.endswith('/') else response
    pretest.js_analysis('http://slow.test',page.copy())
    print('JS',label,sorted(pretest.FINDINGS))
pretest.fetch=orig
for label,response in [('slow',(None,None,b'TimeoutError()')),('dead',(None,None,b"URLError(ConnectionRefusedError(111, 'Connection refused'))")),('healthy',(200,{},b'ok'))]:
    pretest.FINDINGS.clear(); pretest.fetch=lambda *a,_r=response,**kw:_r
    pretest.https_entry('example.test',200,'http://example.test/',{},443)
    print('HTTPS',label,[(x,f['sev']) for x,f in pretest.FINDINGS.items()])
pretest.fetch=orig
s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(); opened=s.getsockname()[1]
c=socket.socket(); c.bind(('127.0.0.1',0)); closed=c.getsockname()[1]; c.close()
pretest.FINDINGS.clear(); pretest.port_checks('127.0.0.1',[opened,closed])
print('PORT listener/dead',opened,closed,[(x,f['sev']) for x,f in pretest.FINDINGS.items()]); s.close()
for url in ['https://example.com:notaport/','https://example.com/']:
    try: print('ORIGIN',url,'=>',pretest._origin(url))
    except Exception as e: print('ORIGIN',url,'=> raises',type(e).__name__)
PY
```

Utskrift:

```text
JS slow ['js-partial']
JS healthy []
HTTPS slow [('https-unreachable', 'info')]
HTTPS dead [('no-https', 'high')]
HTTPS healthy [('no-https-redirect', 'high')]
PORT listener/dead 59983 43161 [('port-59983', 'info')]
ORIGIN https://example.com:notaport/ => raises ValueError
ORIGIN https://example.com/ => ('https', 'example.com', 443)
```

Portnumren väljs dynamiskt och kan skilja sig vid ny körning. Portprovet använde en lokal lyssnande TCP-socket och en bunden/stängd port. Det bekräftar att en accepterande port rapporteras och en stängd port inte gör det; det simulerar inte filtrering eller långsam anslutning på ett externt nät.

För HTTPS-fallet med aktiv HTTP men stängd HTTPS-port 443 ges `no-https` high. Vid timeout blir resultatet i stället informativt och uttryckligen oprövat. När HTTP körs på alternativ port kontrolleras inte HTTPS på den porten; rapporten säger att standardporten är oprövad. JS-provet använder en stubbad timeoutrespons, inte en verkligt långsam extern server.

Självtest:

```text
$ python3 pretest.py --self-test
self-test: 22 förväntade fynd, 0 falska larm på ren fixture, TLS-kontroll prövad
OK
```

## Nya fel i `d6d0ad3..HEAD`

```sh
git diff d6d0ad3..HEAD -- pretest.py
```

Diffen ändrar versionssträngen, `_origin`/credential-origin-hantering, HTTPS-kontrollen från HTTP, JS-fynd vid helt misslyckade bundlehämtningar samt self-test och redigering av URL i statusutskriften. Motproven ovan visar ogiltig port avvisad, JS-timeout utan falskt `js-none`, alternativ HTTP-port tydligt oprövad och credentials endast jämförda efter giltigt origin. Jag körde inte något motprov som visar ett nytt blockerande fel i just den diffen.

## Bedömning

De tre blockerarna från rond 5 är åtgärdade. Slow/dead-värd-proven skiljer oprövade nätvägar från observerade fynd, och rapporten är tydlig om port 443 respektive alternativportar. Jag hittade ingen ny blockerare styrkt av motprov i den avgränsade diffen.

## DOM: WOW
