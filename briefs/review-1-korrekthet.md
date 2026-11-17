UPPDRAG: kritisk granskning av KORREKTHET — falska positiva och falska negativa.

pretest.py är ett verktyg som körs mot en kunds system före ett pentest. Ett falskt positivt förstör
förtroendet; ett falskt negativt är värre, för då tror kunden att ytan är ren.

Gå igenom varje kontroll (id:na finns i add()-anropen) och svara för var och en:
1. När larmar den fel? (träffsäkerhet i regexen, saknad kontext, normal konfiguration som ser farlig ut)
2. Vilket verkligt fall missar den? (språkvarianter, andra moln, andra ramverk, SPA:er, CDN:er)
3. Är info-nivån rätt för det som inte kunde kontrolleras, eller tystnar kontrollen?

Bygg egna motprov: starta en lokal HTTP-server (som self_test gör) som ser ut som ett rimligt system
(WordPress, Next.js, Django, nginx med PHP) och se vad verktyget säger. Ett system som beter sig korrekt
får inte ge några fynd på medium eller högre.

DU ÄR GRANSKARE, INTE BYGGARE
- Ändra INTE pretest.py eller någon annan befintlig fil. Du skriver exakt EN ny fil: research/review-1-korrekthet.md
- Fyra andra granskare arbetar i samma mapp samtidigt. Rör bara din fil.
- Läs hela pretest.py (ca 1300 rader) innan du dömer. Kör den: `python3 pretest.py --self-test` och mot en lokal fixture eller en sajt du äger.
- Varje påstående om koden ska ha `fil:rad` och gå att grepa. Kör kommandot, gissa inte.
- Skriv på svenska.

LEVERABEL: research/review-1-korrekthet.md med
1. ## Fynd — tabell: `fil:rad | allvarlighet (blockerande/allvarlig/mindre/nit) | problem | varför det spelar roll | föreslagen åtgärd`
2. ## Det jag prövade — exakt vilka kommandon/prover du körde och vad de gav
3. ## Vad jag inte kunde avgöra
4. ## DOM: WOW  eller  ## DOM: INTE WOW
   WOW kräver att du inte hittar något blockerande eller allvarligt. Du får inte skriva WOW för att vara
   trevlig: om du inte skulle lita på verktyget i en riktig kundmiljö, är domen INTE WOW. Skriver du
   INTE WOW måste du lista exakt vad som ska ändras för att du ska byta dom — punkterna kommer att
   åtgärdas och du får granska igen.
