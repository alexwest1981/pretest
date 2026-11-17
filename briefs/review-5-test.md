UPPDRAG: kritisk granskning av TESTET — vilka kontroller kan dö tysta?

`python3 pretest.py --self-test` är enda skyddsnätet. Frågan är om det faktiskt fångar en trasig kontroll.
1. Gå igenom varje add()-id och avgör: om den kontrollen slutade fungera i morgon, skulle self-testet bli
   rött? Lista de id:n som INTE prövas av self-testet.
2. Vilka kontroller prövas bara indirekt (TLS, DNS, portar, molnlagring, JWT-weak-secret)?
3. Kan self-testet ge grönt av fel anledning (att ett id skapas av en annan kodväg)?
4. Föreslå de minsta tillägg som skulle göra skillnaden mellan "grönt" och "bevisat grönt". Ange konkret
   kod som behövs, men skriv den inte i pretest.py.
5. Kör --self-test 20 gånger i rad: är den deterministisk? (slumpade id:n, portar, tider)

DU ÄR GRANSKARE, INTE BYGGARE
- Ändra INTE pretest.py eller någon annan befintlig fil. Du skriver exakt EN ny fil: research/review-5-test.md
- Fyra andra granskare arbetar i samma mapp samtidigt. Rör bara din fil.
- Läs hela pretest.py (ca 1300 rader) innan du dömer. Kör den: `python3 pretest.py --self-test` och mot en lokal fixture eller en sajt du äger.
- Varje påstående om koden ska ha `fil:rad` och gå att grepa. Kör kommandot, gissa inte.
- Skriv på svenska.

LEVERABEL: research/review-5-test.md med
1. ## Fynd — tabell: `fil:rad | allvarlighet (blockerande/allvarlig/mindre/nit) | problem | varför det spelar roll | föreslagen åtgärd`
2. ## Det jag prövade — exakt vilka kommandon/prover du körde och vad de gav
3. ## Vad jag inte kunde avgöra
4. ## DOM: WOW  eller  ## DOM: INTE WOW
   WOW kräver att du inte hittar något blockerande eller allvarligt. Du får inte skriva WOW för att vara
   trevlig: om du inte skulle lita på verktyget i en riktig kundmiljö, är domen INTE WOW. Skriver du
   INTE WOW måste du lista exakt vad som ska ändras för att du ska byta dom — punkterna kommer att
   åtgärdas och du får granska igen.
