Din lins är densamma som i rond 1: falska positiva och falska negativa. Verifiera särskilt att
DNS-, cookie-, CORS- och allvarlighetsändringarna inte gav nya falska negativa (t.ex. att en kontroll
nu tiger helt i stället för att larma fel).


ROND 2 — du granskade den här koden i rond 1.
- Din egen rond 1-rapport ligger kvar i research/review-1-korrekthet.md. Läs den först.
- Läs om hela pretest.py (den är ändrad) och kör om dina motprov.
- Nya filen: research/review-1-korrekthet-rond2.md (skriv INTE över rond 1-rapporten).

FÖR VARJE FYND DU GJORDE I ROND 1:
  | ditt fynd (kort) | åtgärdat? (ja/nej/delvis) | hur du verifierade (kommando + resultat) |

SEDAN: leta nya fel i den ändrade koden. Diffen mot det du granskade:
  `git diff 500d7d7..HEAD -- pretest.py`
Var extra misstänksam mot det som lades till för att åtgärda dina fynd — en fix kan bli en ny bugg.

Avsluta med:
## DOM: WOW  eller  ## DOM: INTE WOW
WOW betyder: du skulle låta det här verktyget köras med en kunds credentials mot kundens produktion.
Skriver du INTE WOW: lista exakt vad som återstår, och varför det blockerar.
