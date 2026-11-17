UPPDRAG: kritisk granskning av VERKTYGETS EGEN SÄKERHET.

Det här är ett säkerhetsverktyg som körs med kundens credentials i -H. Ett fel här läcker hemligheter.

Pröva konkret:
1. Kan `-H 'Authorization: …'` eller en cookie läcka till en annan värd? (redirects, cloud_storage,
   sourcemaps, js_analysis, cors-proben — följer något anrop en Location till annan host? Läs fetch() noga.)
2. Hamnar någon hemlighet i rapporten, i --json eller i en fil? Granska _mask() mot varje ställe där ett
   värde skrivs ut, och leta efter värden som INTE maskeras (JWT-payload, -H-värden i evidence, _clip av
   ett svar som innehåller en nyckel).
3. --active-auth: kan den låsa ett konto, skapa state, eller skicka fler anrop än den lovar?
4. Finns obegränsade anrop eller loopar som kan göra skada mot en produktion (rate, antal, storlek)?
5. Skriver verktyget något till disk oväntat?

Kör proverna. Ett påstående utan kommando bakom sig räknas inte.

DU ÄR GRANSKARE, INTE BYGGARE
- Ändra INTE pretest.py eller någon annan befintlig fil. Du skriver exakt EN ny fil: research/review-2-sakerhet.md
- Fyra andra granskare arbetar i samma mapp samtidigt. Rör bara din fil.
- Läs hela pretest.py (ca 1300 rader) innan du dömer. Kör den: `python3 pretest.py --self-test` och mot en lokal fixture eller en sajt du äger.
- Varje påstående om koden ska ha `fil:rad` och gå att grepa. Kör kommandot, gissa inte.
- Skriv på svenska.

LEVERABEL: research/review-2-sakerhet.md med
1. ## Fynd — tabell: `fil:rad | allvarlighet (blockerande/allvarlig/mindre/nit) | problem | varför det spelar roll | föreslagen åtgärd`
2. ## Det jag prövade — exakt vilka kommandon/prover du körde och vad de gav
3. ## Vad jag inte kunde avgöra
4. ## DOM: WOW  eller  ## DOM: INTE WOW
   WOW kräver att du inte hittar något blockerande eller allvarligt. Du får inte skriva WOW för att vara
   trevlig: om du inte skulle lita på verktyget i en riktig kundmiljö, är domen INTE WOW. Skriver du
   INTE WOW måste du lista exakt vad som ska ändras för att du ska byta dom — punkterna kommer att
   åtgärdas och du får granska igen.
