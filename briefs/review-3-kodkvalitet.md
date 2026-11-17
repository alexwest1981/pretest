UPPDRAG: kritisk granskning av KODEN som kod — minsta möjliga, tydligast möjliga.

Mått: en erfaren utvecklare ska kunna läsa filen på en kvart och lita på den. Leta efter:
1. Död kod, oanvända variabler/parametrar (rc som aldrig används, page-argument som inte läses, importer
   som inte behövs).
2. Dubblering: samma logik i två funktioner, samma sträng upprepad, två listor som borde vara en.
3. Namnkollisioner och skuggor (finns det två SECRET_PATTERNS? skuggar en lokal variabel en global?).
4. Felhantering som sväljer fel eller sväljer för mycket (except Exception: pass).
5. Struktur: är en 1300-radersfil rätt form, eller borde något brytas ut? Motivera med antal rader och vad
   som faktiskt blir bättre. "Bryt ut i moduler" utan mätt skäl räknas inte.
6. Annotationer, argparse-helpar, docsträngar: konsekvent?

DU ÄR GRANSKARE, INTE BYGGARE
- Ändra INTE pretest.py eller någon annan befintlig fil. Du skriver exakt EN ny fil: research/review-3-kodkvalitet.md
- Fyra andra granskare arbetar i samma mapp samtidigt. Rör bara din fil.
- Läs hela pretest.py (ca 1300 rader) innan du dömer. Kör den: `python3 pretest.py --self-test` och mot en lokal fixture eller en sajt du äger.
- Varje påstående om koden ska ha `fil:rad` och gå att grepa. Kör kommandot, gissa inte.
- Skriv på svenska.

LEVERABEL: research/review-3-kodkvalitet.md med
1. ## Fynd — tabell: `fil:rad | allvarlighet (blockerande/allvarlig/mindre/nit) | problem | varför det spelar roll | föreslagen åtgärd`
2. ## Det jag prövade — exakt vilka kommandon/prover du körde och vad de gav
3. ## Vad jag inte kunde avgöra
4. ## DOM: WOW  eller  ## DOM: INTE WOW
   WOW kräver att du inte hittar något blockerande eller allvarligt. Du får inte skriva WOW för att vara
   trevlig: om du inte skulle lita på verktyget i en riktig kundmiljö, är domen INTE WOW. Skriver du
   INTE WOW måste du lista exakt vad som ska ändras för att du ska byta dom — punkterna kommer att
   åtgärdas och du får granska igen.
