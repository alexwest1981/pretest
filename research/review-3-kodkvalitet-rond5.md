# Rond 5 — avgörandet

Jag läste rond 4, aktuell `pretest.py` och `git diff 4719d83..HEAD -- pretest.py`. Jag upprepade id/area-motprovet och kontrollerade övriga fyndfält, dict-nyckeln och rapportens target.

## Blockerare från rond 4

| Rond 4-blockerare | Åtgärdad? | Kommandot som visar det |
|---|---|---|
| Hemlighet i `id` eller `area` passerade `_redact` och läckte i JSON-rapporten. | Ja. `add` redigerar nu `fid` innan det används både som dict-nyckel och `id`, samt redigerar `area`. | `python3 - <<'PY'`-motprovet nedan: `dictionary key leaks: False`, `field leaks: ['sev']`, `target leaks: False`, `report JSON leaks: False`. |

```text
$ python3 - <<'PY'
import json, pretest
s='opaque-probe-secret-987654321'
pretest.FINDINGS.clear()
pretest.add('id='+s, 'sev='+s, 'area='+s, 'title='+s,
            evidence='evidence='+s, why='why='+s, fix='fix='+s)
f=next(iter(pretest.FINDINGS.items()))
print('dictionary key leaks:', s in f[0])
print('field leaks:', [k for k,v in f[1].items() if s in str(v)])
print('serialized FINDINGS leaks:', s in json.dumps(pretest.FINDINGS, default=str))
pretest.FINDINGS.clear()
pretest.add('fixed-id', 'info', 'area', 'title')
r=json.loads(pretest.report('https://u:'+s+'@example.test/', as_json=True))
print('target leaks:', s in r['target'])
print('report JSON leaks:', s in json.dumps(r))
PY
dictionary key leaks: False
field leaks: ['sev']
serialized FINDINGS leaks: True
target leaks: False
report JSON leaks: False
```

`sev` går tekniskt sett förbi `_redact` i `add`, men motprovet använder ett ogiltigt allvarlighetsvärde. Verktygets anrop skickar fasta värden från `SEV_ORDER`; `report` räknar och sorterar efter den uppräkningen. Med den faktiska anropsvägen kom inget hemligt värde ut i rapporten. Jag bedömer därför inte detta som blockerare för den angivna domen.

## Granskning av ändringen sedan `4719d83`

Diffen innehåller redigering av id/area och target, justerad klassning och formulering för JWT-fyndet samt en DNS-ändring som räknar ouppklarade A-uppslag som oprövade. De nya redaktionsvägarna klarade det körda motprovet; självtestet inkluderar även URL-userinfo. Inget nytt blockerande fel framkom i diffgranskningen.

```text
$ python3 pretest.py --self-test
self-test: 22 förväntade fynd, 0 falska larm på ren fixture, TLS-kontroll prövad
OK

$ python3 -m py_compile pretest.py
(exit 0)

$ git diff --check
(ingen utskrift; exit 0)
```

## DOM: WOW
