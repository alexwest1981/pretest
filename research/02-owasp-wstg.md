# OWASP Web Security Testing Guide: testkatalogen

## Version och antal

- **Senaste stabila version: WSTG 4.2.** Projektets officiella README säger att arbetet på version 5.0 pågår och hänvisar till v4.2 som senaste stabila utgåva. [belagt: https://github.com/OWASP/wstg]
- **Antal i v4.2: 108 testartiklar.** Jag räknade Markdown-testartiklar i den officiella v4.2-katalogens testträd och uteslöt kategoriöversikter (`00-`) och `README.md`. Detta är en reproducerbar filräkning, inte ett av OWASP uttryckligen publicerat totalsvar. [belagt: https://api.github.com/repos/OWASP/wstg/git/trees/v4.2?recursive=1]
- **Arbetsversion 5.0: 137 testartiklar enligt samma filräkning.** Katalogträdet innehåller även en ny WebAssembly-kategori; 5.0 är fortfarande under arbete och siffran kan ändras. [belagt: https://api.github.com/repos/OWASP/wstg/git/trees/master?recursive=1] [belagt: https://github.com/OWASP/wstg]

## Kategorier och centrala tester

Listan nedan använder stabila v4.2-ID:n. “Centrala” är ett urval för orientering, inte en officiell OWASP-prioritering. [resonemang]

### INFO — Informationsinhämtning
Kartläggning av mål, teknik, innehåll, inmatningspunkter och applikationsflöden. [belagt: https://github.com/OWASP/wstg/blob/v4.2/document/4-Web_Application_Security_Testing/01-Information_Gathering/README.md]

- `WSTG-INFO-01` Genomför sökmotorrekognosering för informationsläckage. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/01-Information_Gathering]
- `WSTG-INFO-02` Identifiera webbserver. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/01-Information_Gathering]
- `WSTG-INFO-04` Identifiera attackytan. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/01-Information_Gathering]
- `WSTG-INFO-06` Identifiera applikationens ingångspunkter. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/01-Information_Gathering]
- `WSTG-INFO-07` Kartlägg exekveringsvägar genom applikationen. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/01-Information_Gathering]

[Testartiklarna](https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/01-Information_Gathering) [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/01-Information_Gathering]

### CONF — Konfiguration och driftsättning
Granskning av nätverks- och plattformskonfiguration, exponerade filer/gränssnitt, HTTP-funktioner och säkerhetskontroller i driftsättningen. [belagt: https://github.com/OWASP/wstg/blob/v4.2/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/README.md]

- `WSTG-CONF-01` Testa nätverksinfrastrukturens konfiguration. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management]
- `WSTG-CONF-02` Testa applikationsplattformens konfiguration. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management]
- `WSTG-CONF-03` Testa hantering av filändelser för känslig information. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management]
- `WSTG-CONF-04` Granska gamla säkerhetskopior och olistade filer för känslig information. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management]
- `WSTG-CONF-06` Testa HTTP-metoder. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management]
- `WSTG-CONF-12` Testa Content Security Policy. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management]

[Testartiklarna](https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management) [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management]

### IDNT — Identitetshantering
Granskning av roller, registrering, kontoskapande och användarnamnspolicy. [belagt: https://github.com/OWASP/wstg/blob/v4.2/document/4-Web_Application_Security_Testing/03-Identity_Management/README.md]

- `WSTG-IDNT-01` Testa rolldefinitioner. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/03-Identity_Management]
- `WSTG-IDNT-02` Testa användarregistreringsprocessen. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/03-Identity_Management]
- `WSTG-IDNT-03` Testa kontoprovisionering. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/03-Identity_Management]
- `WSTG-IDNT-04` Testa kontoenumerering och gissningsbara användarkonton. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/03-Identity_Management]
- `WSTG-IDNT-05` Testa svag eller ej upprätthållen användarnamnspolicy. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/03-Identity_Management]

[Testartiklarna](https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/03-Identity_Management) [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/03-Identity_Management]

### ATHN — Autentisering
Granskning av inloggning, autentiseringsfaktorer, lösenord, återställning, låsning och kringgående av autentisering. [belagt: https://github.com/OWASP/wstg/blob/v4.2/document/4-Web_Application_Security_Testing/04-Authentication/README.md]

- `WSTG-ATHN-01` Testa autentiseringsuppgifter över krypterad kanal. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/04-Authentication]
- `WSTG-ATHN-02` Testa standardautentiseringsuppgifter. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/04-Authentication]
- `WSTG-ATHN-03` Testa svag kontolåsning. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/04-Authentication]
- `WSTG-ATHN-04` Testa kringgående av autentiseringsschema. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/04-Authentication]
- `WSTG-ATHN-07` Testa lösenordsstyrka. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/04-Authentication]
- `WSTG-ATHN-09` Testa svag återställning av lösenord. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/04-Authentication]

[Testartiklarna](https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/04-Authentication) [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/04-Authentication]

### ATHZ — Auktorisering
Test av åtkomstkontroll: om användare och roller kan nå resurser eller funktioner de inte ska ha åtkomst till. [belagt: https://github.com/OWASP/wstg/blob/v4.2/document/4-Web_Application_Security_Testing/05-Authorization/README.md]

- `WSTG-ATHZ-01` Testa katalogtraversering/filinkludering. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/05-Authorization]
- `WSTG-ATHZ-02` Testa kringgående av auktoriseringsschema. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/05-Authorization]
- `WSTG-ATHZ-03` Testa eskalering av privilegier. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/05-Authorization]
- `WSTG-ATHZ-04` Testa osäkra direkta objektreferenser. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/05-Authorization]

[Testartiklarna](https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/05-Authorization) [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/05-Authorization]

### SESS — Sessionshantering
Granskning av sessionstoken, cookies, livscykel, fixering, CSRF och utloggning. [belagt: https://github.com/OWASP/wstg/blob/v4.2/document/4-Web_Application_Security_Testing/06-Session_Management/README.md]

- `WSTG-SESS-01` Testa sessionshanteringsschema. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/06-Session_Management]
- `WSTG-SESS-02` Testa attribut för cookies. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/06-Session_Management]
- `WSTG-SESS-03` Testa sessionsfixering. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/06-Session_Management]
- `WSTG-SESS-04` Testa exponerade sessionsvariabler. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/06-Session_Management]
- `WSTG-SESS-05` Testa CSRF. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/06-Session_Management]
- `WSTG-SESS-06` Testa utloggning och sessionstimeout. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/06-Session_Management]

[Testartiklarna](https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/06-Session_Management) [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/06-Session_Management]

### INPV — Inmatningsvalidering och injektion
Test av hur applikationen hanterar angriparkontrollerade värden i parametrar, interpretrar, databaser, mallar, filer och protokoll. [belagt: https://github.com/OWASP/wstg/blob/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation/README.md]

- `WSTG-INPV-01` Testa reflekterad cross-site scripting (XSS). [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation]
- `WSTG-INPV-02` Testa lagrad XSS. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation]
- `WSTG-INPV-05` Testa SQL-injektion. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation]
- `WSTG-INPV-07` Testa XML-injektion. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation]
- `WSTG-INPV-11` Testa LDAP-injektion. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation]
- `WSTG-INPV-18` Testa server-side template injection. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation]

[Testartiklarna](https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation) [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation]

### ERRH — Felhantering
Granskning av felmeddelanden och stackspår som kan avslöja känsliga detaljer eller kontrollflöde. [belagt: https://github.com/OWASP/wstg/blob/v4.2/document/4-Web_Application_Security_Testing/08-Error_Handling/README.md]

- `WSTG-ERRH-01` Testa felaktig felhantering. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/08-Error_Handling]
- `WSTG-ERRH-02` Testa stackspår. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/08-Error_Handling]

[Testartiklarna](https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/08-Error_Handling) [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/08-Error_Handling]

### CRYP — Kryptografi
Granskning av transportskydd, okrypterade kanaler och kryptografiska primitiver. [belagt: https://github.com/OWASP/wstg/blob/v4.2/document/4-Web_Application_Security_Testing/09-Weak_Cryptography/README.md]

- `WSTG-CRYP-01` Testa svag TLS. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/09-Weak_Cryptography]
- `WSTG-CRYP-02` Testa padding oracle. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/09-Weak_Cryptography]
- `WSTG-CRYP-03` Testa känslig information över okrypterade kanaler. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/09-Weak_Cryptography]
- `WSTG-CRYP-04` Testa svaga kryptografiska primitiver. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/09-Weak_Cryptography]

[Testartiklarna](https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/09-Weak_Cryptography) [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/09-Weak_Cryptography]

### BUSL — Affärslogik
Test av validering och affärsregler, arbetsflöden, begränsningar, missbruk och betalningar. [belagt: https://github.com/OWASP/wstg/blob/v4.2/document/4-Web_Application_Security_Testing/10-Business_Logic/README.md]

- `WSTG-BUSL-01` Testa validering av affärslogikdata. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/10-Business_Logic]
- `WSTG-BUSL-02` Testa möjligheten att förfalska förfrågningar. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/10-Business_Logic]
- `WSTG-BUSL-04` Testa tidsberoende processer. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/10-Business_Logic]
- `WSTG-BUSL-05` Testa gränser för antal funktionsanrop. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/10-Business_Logic]
- `WSTG-BUSL-06` Testa kringgående av arbetsflöden. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/10-Business_Logic]
- `WSTG-BUSL-10` Testa betalningsfunktioner. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/10-Business_Logic]

[Testartiklarna](https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/10-Business_Logic) [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/10-Business_Logic]

### CLNT — Klientsida
Granskning av webbläsarens hantering av skript, DOM, ursprung, resurser, WebSockets, lagring och inramning. [belagt: https://github.com/OWASP/wstg/blob/v4.2/document/4-Web_Application_Security_Testing/11-Client-side/README.md]

- `WSTG-CLNT-01` Testa DOM-baserad XSS. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/11-Client-side]
- `WSTG-CLNT-02` Testa JavaScript-körning. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/11-Client-side]
- `WSTG-CLNT-04` Testa omdirigering av URL på klientsidan. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/11-Client-side]
- `WSTG-CLNT-07` Testa CORS. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/11-Client-side]
- `WSTG-CLNT-09` Testa clickjacking. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/11-Client-side]
- `WSTG-CLNT-12` Testa lagring i webbläsaren. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/11-Client-side]

[Testartiklarna](https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/11-Client-side) [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/11-Client-side]

### APIT — API-testning
Kartläggning och test av API-specifika exponerings- och auktoriseringsproblem samt protokoll eller API-teknik. [belagt: https://github.com/OWASP/wstg/blob/v4.2/document/4-Web_Application_Security_Testing/12-API_Testing/README.md]

- `WSTG-APIT-01` API-rekognosering. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/12-API_Testing]
- `WSTG-APIT-02` API: bristande objektnivåauktorisering. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/12-API_Testing]
- `WSTG-APIT-03` Överdriven dataexponering. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/12-API_Testing]
- `WSTG-APIT-04` API: bristande funktionsnivåauktorisering. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/12-API_Testing]
- `WSTG-APIT-99` GraphQL-testning. [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/12-API_Testing]

[Testartiklarna](https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/12-API_Testing) [belagt: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/12-API_Testing]

## Kategorier som kräver inloggning

**Ingen av de tolv kategorierna är helt omöjlig att testa utan inloggning.** Det är en slutsats av testernas olika mål: flera kan göras mot publika ytor, anonyma sessioner eller öppna API:er. [resonemang]

Auktorisering (`ATHZ`) kräver i praktiken normalt minst två identitets-/behörighetslägen för att jämföra tillåten och otillåten åtkomst; utan konton blir täckningen därför kraftigt begränsad. [resonemang] Vissa sessionstester (`SESS`) kan utföras före inloggning eftersom även anonyma besökare kan få sessionscookies; andra kräver autentiserade arbetsflöden. [resonemang] Guideintroduktionen beskriver informationsinhämtning som passiv utforskning av applikationen som slutanvändare och noterar att autentiseringsformulär är möjliga ingångspunkter. [belagt: https://github.com/OWASP/wstg/blob/v4.2/document/4-Web_Application_Security_Testing/00-Introduction_and_Objectives/README.md]

## Tester där automatisering ofta missar viktiga fynd

WSTG ger ingen officiell lista över test-ID:n som verktyg missar. Följande är därför praktiska bedömningar: tester med affärskontext, flera roller, tillståndsövergångar eller manuell granskning av innehåll är särskilt svåra att automatisera fullständigt. [resonemang]

- `WSTG-INFO-05` Granska webbsidans innehåll för informationsläckage: automatisering kan hitta mönster, men missar ofta kontextuell betydelse av kommenterar, dolda fält eller dokument. [resonemang]
- `WSTG-ATHZ-02` Kringgående av auktoriseringsschema: kräver att testaren identifierar roller, resurser och förväntad åtkomst; generiska skannrar saknar ofta den modellen. [resonemang]
- `WSTG-ATHZ-04` Osäkra direkta objektreferenser: verktyg kan hitta ID-parametrar men behöver jämföra objekt mellan konton och avgöra om åtkomsten är otillåten. [resonemang]
- `WSTG-BUSL-06` Kringgående av arbetsflöden: kräver förståelse av giltiga steg och verksamhetsregler, så generisk fuzzning ser sällan att en process hoppats över. [resonemang]
- `WSTG-BUSL-10` Betalningsfunktioner: verifiering kräver förståelse av order-, pris-, rabatt- och betalningsflöden samt testmiljödata. [resonemang]
- `WSTG-CLNT-01` DOM-baserad XSS: källor och sinks kan delvis detekteras statiskt/dynamiskt, men exekveringsvägar, sanering och exploaterbarhet behöver ofta manuell kontroll i webbläsaren. [resonemang]
- `WSTG-APIT-02` Bristande objektnivåauktorisering: automatisering missar ofta jämförelsen mellan olika användares objekt och affärsmässig åtkomstpolicy. [resonemang]

## Innehåll i en testrapport

WSTG beskriver en föreslagen rapportstruktur, inte bindande krav. Den anger följande rekommenderade delar: [belagt: https://github.com/OWASP/wstg/blob/master/document/5-Reporting/01-Reporting_Structure.md]

- **Inledning:** versionshistorik, innehållsförteckning, team och kompetens, omfattning, begränsningar, tidslinje och eventuell ansvarsfriskrivning. [belagt: https://github.com/OWASP/wstg/blob/master/document/5-Reporting/01-Reporting_Structure.md]
- **Sammanfattning för ledning:** testets syfte/verksamhetsbehov, viktiga fynd i verksamhetskontext och strategiska rekommendationer. [belagt: https://github.com/OWASP/wstg/blob/master/document/5-Reporting/01-Reporting_Structure.md]
- **Fyndöversikt:** referens-ID, titel och risknivå. [belagt: https://github.com/OWASP/wstg/blob/master/document/5-Reporting/01-Reporting_Structure.md]
- **Detaljer per fynd:** exploaterbarhet/sannolikhet, påverkan, riskklassning och hur den bestäms, sårbarhetsbeskrivning, reproduktions-/exploateringssteg, möjlig skada, åtgärdsråd och relevanta resurser. Känsliga exempeldata ska maskeras. [belagt: https://github.com/OWASP/wstg/blob/master/document/5-Reporting/01-Reporting_Structure.md]
- **Bilagor vid behov:** metodik, förklaringar av allvarlighets-/risknivåer, rensat verktygsunderlag och checklista över genomförda tester. Reproducerbara artefakter som curl-exempel, PoC, HAR eller enkla skript kan också hjälpa vid verifiering och omtest. [belagt: https://github.com/OWASP/wstg/blob/master/document/5-Reporting/01-Reporting_Structure.md]
- Rapporten bör vara begriplig både för ledning och tekniska läsare, och skyddas/krypteras så att endast avsedd mottagare kan använda den. [belagt: https://github.com/OWASP/wstg/blob/master/document/5-Reporting/01-Reporting_Structure.md]

## Vad jag inte kunde belägga

- OWASP publicerar inte i de här källorna en officiell, uttrycklig totalsiffra för antalet testartiklar; 108 respektive 137 är min räkning av versionsmärkta katalogträd med den angivna avgränsningen. [belagt: https://github.com/OWASP/wstg] [belagt: https://api.github.com/repos/OWASP/wstg/git/trees/v4.2?recursive=1]
- Jag kunde inte belägga en officiell OWASP-rangordning av “mest centrala” tester eller en officiell lista över exakt vilka test-ID:n automatiseringsverktyg missar. Urvalen och automatiseringsbedömningarna ovan är redovisade som resonemang. [resonemang]
- Inget WSTG-avsnitt säger uttryckligen att en hel kategori är absolut omöjlig utan autentisering. Bedömningen att ingen kategori som helhet uppfyller det villkoret är därför en syntes av testernas natur, inte ett direkt citat. [resonemang]
