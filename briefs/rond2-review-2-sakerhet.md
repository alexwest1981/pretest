Din lins är densamma: verktygets egen säkerhet. Verifiera själv credential-scopningen mot två
lokala servrar (samma värd/annat port och annan värd), och att _redact() täcker ALLA evidensvägar —
bygg en fixture där en hemlighet finns i .env, i en cookie, i en HTML-kommentar och i ett felmeddelande,
och granska både textrapporten och --json.


ROND 2 — du granskade den här koden i rond 1.
- Din egen rond 1-rapport ligger kvar i research/review-2-sakerhet.md. Läs den först.
- Läs om hela pretest.py (den är ändrad) och kör om dina motprov.
- Nya filen: research/review-2-sakerhet-rond2.md (skriv INTE över rond 1-rapporten).

FÖR VARJE FYND DU GJORDE I ROND 1:
  | ditt fynd (kort) | åtgärdat? (ja/nej/delvis) | hur du verifierade (kommando + resultat) |

SEDAN: leta nya fel i den ändrade koden. Diffen mot det du granskade:
  `git diff 500d7d7..HEAD -- pretest.py`
Var extra misstänksam mot det som lades till för att åtgärda dina fynd — en fix kan bli en ny bugg.

Avsluta med:
## DOM: WOW  eller  ## DOM: INTE WOW
WOW betyder: du skulle låta det här verktyget köras med en kunds credentials mot kundens produktion.
Skriver du INTE WOW: lista exakt vad som återstår, och varför det blockerar.
