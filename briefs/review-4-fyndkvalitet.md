UPPDRAG: kritisk granskning av FYNDEN som konsumenten läser.

Läs tio fynd som verktyget kan producera (kör det mot en lokal fixture) och döm dem som en kund skulle:
1. Allvarlighetsgrad: är critical/high/medium kalibrerat mot vad fyndet ger en angripare? Saknat
   X-Permitted-Cross-Domain-Policies som low — rimligt? alg=none som critical — rätt?
2. Bevis: räcker bevis-raden för att en utvecklare ska kunna reproducera fyndet utan att fråga?
3. Åtgärden: är den genomförbar för den som äger systemet, eller bara en princip?
4. Språk: svenska, konsekvent terminologi (cookie vs kaka, fynd vs problem), inga AI-ismer, inga
   särskrivningar, inga engelska fragment i svensk text. Lista varje avvikelse.
5. Rapporten som helhet: om du fick den av en konsult, vad skulle du ifrågasätta?

DU ÄR GRANSKARE, INTE BYGGARE
- Ändra INTE pretest.py eller någon annan befintlig fil. Du skriver exakt EN ny fil: research/review-4-fyndkvalitet.md
- Fyra andra granskare arbetar i samma mapp samtidigt. Rör bara din fil.
- Läs hela pretest.py (ca 1300 rader) innan du dömer. Kör den: `python3 pretest.py --self-test` och mot en lokal fixture eller en sajt du äger.
- Varje påstående om koden ska ha `fil:rad` och gå att grepa. Kör kommandot, gissa inte.
- Skriv på svenska.

LEVERABEL: research/review-4-fyndkvalitet.md med
1. ## Fynd — tabell: `fil:rad | allvarlighet (blockerande/allvarlig/mindre/nit) | problem | varför det spelar roll | föreslagen åtgärd`
2. ## Det jag prövade — exakt vilka kommandon/prover du körde och vad de gav
3. ## Vad jag inte kunde avgöra
4. ## DOM: WOW  eller  ## DOM: INTE WOW
   WOW kräver att du inte hittar något blockerande eller allvarligt. Du får inte skriva WOW för att vara
   trevlig: om du inte skulle lita på verktyget i en riktig kundmiljö, är domen INTE WOW. Skriver du
   INTE WOW måste du lista exakt vad som ska ändras för att du ska byta dom — punkterna kommer att
   åtgärdas och du får granska igen.
