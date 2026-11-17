# Vad mäts under ett penetrationstest?

**Läsnyckel.** [resonemang] betyder att punkten är en praktisk slutsats/syntes, inte ett uttryckligt krav i källan. PTES-källan nedan är ett offentligt GitHub-fork av dokumentationen; den säger själv att den är en inofficiell fork. [belagt: https://raw.githubusercontent.com/pentest-standard/docs/master/index.rst]

## 1. PTES: sju faser och vad som går att lämna över

PTES delar upp testet i sju faser. Standarden garanterar inte en enda obligatorisk, kvantitativ mätstorhet eller mallleverans per fas. Tabellen skiljer därför fasernas syfte från rimliga granskningsbara artefakter. [belagt: https://raw.githubusercontent.com/pentest-standard/docs/master/index.rst] [resonemang]

| Fas | Mätbar/granskningsbar leverans |
|---|---|
| Förberedelser och avgränsning (Pre-engagement) | Avtalad omfattning, mål, tidsfönster, kontaktvägar och regler för testet; dessa kan kontrolleras mot det godkända uppdragsunderlaget. [belagt: https://raw.githubusercontent.com/pentest-standard/docs/master/preengagement_interactions.rst] |
| Informationsinhämtning (Intelligence Gathering) | Inventering och dokumentation av insamlad information och identifierade exponerade tillgångar, med metod/nivå så det går att granska vad som undersökts. [belagt: https://raw.githubusercontent.com/pentest-standard/docs/master/intelligence_gathering.rst] [resonemang] |
| Hotmodellering (Threat Modeling) | Dokumenterade hotaktörer, mål/tillgångar, hot och prioriterade angreppsscenarier. Det är en modellerad bedömning, inte ett objektivt antal sårbarheter. [belagt: https://raw.githubusercontent.com/pentest-standard/docs/master/threat_modeling.rst] [resonemang] |
| Sårbarhetsanalys (Vulnerability Analysis) | Lista över misstänkta och verifierade svagheter, metod och evidens; skilj bekräftade fynd från hypoteser/skannerutdata. [belagt: https://raw.githubusercontent.com/pentest-standard/docs/master/vulnerability_analysis.rst] [resonemang] |
| Exploatering (Exploitation) | Dokumenterade lyckade och misslyckade försök, åtkomstnivå och bevis för att en svaghet faktiskt gick att utnyttja inom reglerna. [belagt: https://raw.githubusercontent.com/pentest-standard/docs/master/exploitation.rst] [resonemang] |
| Efter exploatering (Post-exploitation) | Bevis på uppnådd åtkomst och åtkomst till avtalade mål/data, möjliga fortsatta vägar samt dokumenterad sanering/hantering av insamlad data. [belagt: https://raw.githubusercontent.com/pentest-standard/docs/master/post_exploitation.rst] [resonemang] |
| Rapportering (Reporting) | Slutrapport med omfattning, angreppsväg, evidens, klassificering/prioritering och åtgärdsrekommendationer. [belagt: https://raw.githubusercontent.com/pentest-standard/docs/master/reporting.rst] |

Det centrala mätbara resultatet hos PTES är alltså främst spårbar dokumentation av vad som omfattades, vad som upptäcktes och vad testaren faktiskt kunde åstadkomma; själva faslistan är inte en poängskala. [belagt: https://raw.githubusercontent.com/pentest-standard/docs/master/index.rst] [resonemang]

## 2. NIST SP 800-115: metoder och täckning

NIST grupperar teknikerna i tre klasser. [belagt: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf]

- **Granskningstekniker:** passiv granskning av dokumentation, loggar, regeluppsättningar, systemkonfiguration, nätverkstrafik och filintegritet; oftast manuella. De kan hitta process- och konfigurationsbrister och ger låg påverkan, men dokumentgranskning visar inte i sig att kontrollerna är korrekt implementerade. [belagt: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf]
- **Målidentifiering och analys:** nätverksupptäckt, port-/tjänsteidentifiering, sårbarhetsskanning, trådlös skanning och applikationssäkerhetsgranskning. Ofta verktygsstödd; identifierar system, portar, tjänster och möjliga sårbarheter, alltså bra bredd för inventering och hypoteser. [belagt: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf]
- **Validering av sårbarheter:** lösenordsknäckning, penetrationstest, social manipulation och applikationssäkerhetstest. Kan vara manuella eller automatiserade beroende på teknik och testteamets kompetens; syftet är att bekräfta att svagheter finns. [belagt: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf]

NIST säger uttryckligen att ingen enskild teknik ger en fullständig bild och rekommenderar att lämpliga metoder kombineras. Den anger inte någon universell procentuell täckning per metod eller ett standardiserat heltäckande testpaket; metodvalet ska styras av mål och krav. [belagt: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf]

## 3. OSSTMM: attackyta och kvantifiering

OSSTMM 3 definierar attackytan som den oskyddade delen av testets omfattning för en definierad angreppsvektor. Den anger fem kanaler som ska undersökas separat: mänsklig, fysisk, trådlös, telekommunikation och datanät. [belagt: https://www.isecom.org/OSSTMM.3.pdf]

**RAV** (Risk Assessment Value) är OSSTMM 3:s mått på attackytans storlek genom kvantitativ balans mellan verksamhet/interaktioner, begränsningar och kontroller. I manualens skala är 100 RAV beskrivet som balans; värden under 100 signalerar otillräckliga kontroller/större exponerad yta och över 100 kan betyda överflödiga kontroller som själva medför interaktioner och komplexitet. [belagt: https://www.isecom.org/OSSTMM.3.pdf]

OSSTMM skiljer RAV från risk: RAV mäter attackytan och ger underlag för att analysera risk, men avgör inte om en viss aktör kommer att angripa målet. Manualen beskriver även Delta som avståndet från balans och Actual Security som en mer lättolkad sammanvägning för jämförelser. [belagt: https://www.isecom.org/OSSTMM.3.pdf]

Versionsnot: ISECOM:s nuvarande webbplats presenterar OSSTMM 4 som en ny revision med omformulerat RAV. Beskrivningen ovan gäller uttryckligen den nedladdningsbara OSSTMM 3-manualen, inte den ännu annorlunda OSSTMM 4-mätningen. [belagt: https://isecom.org/osstmm.html] [belagt: https://www.isecom.org/OSSTMM.3.pdf]

## 4. Krävs återtest?

I de granskade kärndokumenten (PTES, NIST SP 800-115 och OSSTMM 3) kunde jag inte belägga ett uttryckligt generellt krav på att samma testare måste återtesta alla åtgärdade fynd. NIST beskriver sårbarhetsvalidering och åtgärdsrekommendationer, men det är inte i sig ett krav på efterföljande återtest. [belagt: https://raw.githubusercontent.com/pentest-standard/docs/master/index.rst] [belagt: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf] [belagt: https://www.isecom.org/OSSTMM.3.pdf] [resonemang]

Som jämförelse kräver PCI DSS:s vägledning för penetrationstest att testaren efter åtgärd återtestar identifierade exploaterbara sårbarheter för att kontrollera att nya kontroller minskar den ursprungliga risken; vid betydande ändringar kan riskbedömning avgöra om ett fullständigt omtest behövs. Detta är PCI-vägledning, ei PTES/NIST/OSSTMM-krav. [belagt: https://www.pcisecuritystandards.org/documents/Penetration-Testing-Guidance-v1_1.pdf] [resonemang]

## 5. Vad kan inte automatiseras fullt ut?

NIST skiljer mellan tekniker som vanligen automatiseras (exempelvis målidentifiering/skanning) och tekniker som vanligen görs manuellt (exempelvis granskning); sårbarhetsvalidering kan vara endera. Därför kan ett skannerresultat inte ensamt likställas med ett bekräftat exploaterbart fynd eller en fullständig säkerhetsbedömning. [belagt: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf] [resonemang]

Dokumentens modell gör följande till mänskligt omdömesarbete: välja relevanta metoder utifrån mål, väga affärskontext/hotmodell, tolka om indikationer faktiskt är sårbarheter, formulera genomförbara angreppsvägar och bedöma konsekvens/prioritet. Viss evidensinsamling och upprepning kan automatiseras; slutsatserna kräver kvalificerad tolkning. [belagt: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf] [belagt: https://raw.githubusercontent.com/pentest-standard/docs/master/threat_modeling.rst] [belagt: https://raw.githubusercontent.com/pentest-standard/docs/master/reporting.rst] [resonemang]

## 6. Fem punkter som ofta bör finnas i ett kommersiellt anbud

Ramverken föreskriver inte att varje kommersiellt anbud måste ha exakt fem testpunkter. Följande är därför en praktisk syntes av återkommande testmoment och leveranser, inte en verifierad marknadsundersökning av alla anbud. [belagt: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf] [belagt: https://raw.githubusercontent.com/pentest-standard/docs/master/index.rst] [resonemang]

1. **Omfattning, tillgångar och regler:** system/domäner/IP, tidsfönster, tillåten påverkan, undantag och kontaktvägar. [belagt: https://raw.githubusercontent.com/pentest-standard/docs/master/preengagement_interactions.rst] [resonemang]
2. **Kartläggning och identifiering:** inventera nåbara värdar, portar, tjänster, webb/applikationsytor och relevanta tekniker. [belagt: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf] [resonemang]
3. **Sårbarhetsanalys och validering:** identifiera, triagera och bekräfta relevanta svagheter, med redovisning av falska positiva och begränsningar. [belagt: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf] [resonemang]
4. **Kontrollerade exploaterings-/åtkomstförsök:** visa om de bekräftade svagheterna ger faktisk åtkomst eller affärspåverkan, inom godkända regler. [belagt: https://raw.githubusercontent.com/pentest-standard/docs/master/exploitation.rst] [resonemang]
5. **Rapport, prioriterade åtgärder och återtest som separat omfattning:** leverera evidens och rekommendationer; erbjud återtest som tydligt avgränsat moment eftersom de tre ramverken inte gör det till ett generellt obligatoriskt moment. [belagt: https://raw.githubusercontent.com/pentest-standard/docs/master/reporting.rst] [belagt: https://www.pcisecuritystandards.org/documents/Penetration-Testing-Guidance-v1_1.pdf] [resonemang]

## Vad jag inte kunde belägga

- Jag kunde inte belägga att PTES, NIST SP 800-115 eller OSSTMM 3 föreskriver ett enda obligatoriskt kvantitativt mätetal för varje fas; PTES-fasernas artefakter i tabellen är granskningsbara utdata/syntes, inte en officiell faspoäng. [belagt: https://raw.githubusercontent.com/pentest-standard/docs/master/index.rst] [belagt: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf] [belagt: https://www.isecom.org/OSSTMM.3.pdf] [resonemang]
- Jag kunde inte belägga en universell fempunktslista som förekommer i praktiskt taget varje kommersiellt pentest-anbud; femman ovan är en upphandlingsmässig sammanställning. [resonemang]
- Den citerade PCI-guidance-länken behöver valideras vid framtida användning; i den här genomgången stödde jag jämförelsen mot PCI:s offentliga vägledning via sökträff, men kunde inte själv få en verifierbar `curl`-hämtning av just den länken. Ta därför inte PCI-jämförelsen som primärbelagd enligt arbetsregeln. [resonemang]
