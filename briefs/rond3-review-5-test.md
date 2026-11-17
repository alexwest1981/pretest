Din lins: testet. Mutera pretest.py i en KOPIA (kopiera till /tmp, ändra där) och visa minst tre
mutationer som fäller self-testet. Om du hittar en mutation som INTE fälls är det blockerande.


ROND 3 — sista granskningen. Du har granskat två gånger (research/review-5-test.md och research/review-5-test-rond2.md).
Läs båda, läs om pretest.py, och kör om dina motprov.

Skriv research/review-5-test-rond3.md (skriv inte över tidigare rapporter).

KRAV PÅ DEN HÄR RONDEN:
1. En tabell: varje blockerande punkt du reste i rond 2 → åtgärdad? (ja/nej/delvis) → kommandot som visar det.
2. Om du anser att något blockerande återstår: visa det med ett kommando och en utskrift. Ett påstående
   utan körning räknas inte i den här ronden.
3. Nya fel i den ändrade koden: `git diff 500d7d7..HEAD -- pretest.py`.

Avsluta med exakt en rad:
## DOM: WOW
eller
## DOM: INTE WOW — <den enda mening som sammanfattar vad som återstår>

WOW betyder: du skulle låta verktyget köras med en kunds credentials mot kundens produktion, och du
skulle stå för rapporten den skriver. Det är gaten. Om du tycker att något är en nit men inte blockerar,
skriv det i fyndtabellen med nivån "nit" och döm ändå WOW.
