UPPDRAG: OWASP Web Security Testing Guide (WSTG) — den fullständiga testkatalogen.

Svara på dessa frågor med källor:
1. Lista WSTG:s kategorier med deras kodbokstäver (INFO, CONF, IDNT, ATHN, ATHZ, SESS, INPV, ERRH, CRYP, BUSL, CLNT, APIT) och vad varje kategori täcker.
2. Ange det totala antalet tester i aktuell WSTG-version (v4.2 eller v5.0 — kontrollera vilken som är aktuell och säg det).
3. För varje kategori: namnge 3–6 konkreta tester (med test-ID, t.ex. WSTG-ATHZ-01) som är de mest centrala.
4. Vilka kategorier är helt omöjliga att göra utan inloggning/autentisering?
5. Vilka enskilda tester är kända för att automationsverktyg missar (ange test-ID och varför)?
6. Vad kräver WSTG att en testrapport ska innehålla?

REGLER
- Skriv på svenska. Ingen språkdrift (inte finska, inte engelska stycken).
- Rör ingen kod. Ändra inga befintliga filer. Skriv EXAKT en ny fil: research/02-owasp-wstg.md
- Andra agenter arbetar i samma mapp samtidigt — skriv bara i din egen fil.
- Hämta varje URL du citerar själv med `curl -sL` (inte bara HEAD; vissa servrar avvisar HEAD med 404).
- Märk varje påstående: [belagt: <url>] eller [resonemang].
- Avsluta med rubriken `## Vad jag inte kunde belägga`.
- Ingen bildfråga: du kan inte se bilder, håll dig till textkällor.
