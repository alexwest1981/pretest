Din lins: testet. Mutera i en kopia och visa att minst tre mutationer fäller self-testet, inklusive att TLS-kontrollen tas bort ur scan().


ROND 5 — avgörandet.

Läs research/review-5-test-rond4.md (din rond 4), läs om pretest.py, kör dina motprov.
Skriv research/review-5-test-rond5.md.

Tabell: varje blockerare du reste i rond 4 → åtgärdad? → kommandot som visar det.
Leta sedan efter nya blockerare i det som ändrades: `git diff 4719d83..HEAD -- pretest.py`.

DOMEN (oförändrad, och bara den):
  "Jag skulle köra pretest med kundens credentials mot kundens produktion för att få underlag
   inför ett pentest, och stå för den rapport den skriver."
En nit, ett förbättringsförslag eller en begränsning som rapporten själv skriver ut är inte skäl
för INTE WOW. Ny blockerare kräver ett kört motprov.

Sista raden, exakt:
## DOM: WOW
## DOM: INTE WOW — <en mening: vad som återstår>
