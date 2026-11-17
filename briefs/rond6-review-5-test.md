Din lins: testet. Mutera i en kopia: ta bort tls_checks ur scan(), ändra jwt-weak-secret till low, och kortslut _redact — alla tre ska fällas.


ROND 6 — verifiering av dina rond 5-punkter.

Läs research/review-5-test-rond5.md, läs om pretest.py, kör dina motprov. Skriv research/review-5-test-rond6.md.

Tabell: dina rond 5-blockerare → åtgärdade? → kommandot som visar det.
Nya fel: bara i diffen `git diff d6d0ad3..HEAD -- pretest.py`.

DOMEN (oförändrad):
  "Jag skulle köra pretest med kundens credentials mot kundens produktion för att få underlag
   inför ett pentest, och stå för den rapport den skriver."
En nit eller en utskriven begränsning är inte skäl för INTE WOW. Ny blockerare kräver ett kört motprov.

Sista raden, exakt:
## DOM: WOW
## DOM: INTE WOW — <en mening: vad som återstår>
