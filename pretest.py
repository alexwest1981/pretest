#!/usr/bin/env python3
"""pretest — automated pre-pentest self-assessment.

Runs the mechanical half of a pentest: exposed artifacts, transport/TLS
hygiene, cookie and CORS misconfig, DNS/e-mail spoofing surface, dangling
subdomains, open ports, secrets in the repo, known-vulnerable dependencies.
Everything it finds is something a paid pentester would have found anyway in
the first hour; the point is to spend that budget on authorization, business
logic and attack chains instead.

Read-only: GET/HEAD, DNS lookups (DoH), optional TCP connect. No exploitation,
no fuzzing, no load.

ONLY run this against systems you own or have written permission to test.

Usage:
  pretest.py --url https://example.se --domain example.se
  pretest.py --url https://example.se --repo ~/Projects/myapp --json out.json
  pretest.py --url https://example.se --fail-on high   # CI gate
  pretest.py --self-test
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import socket
import string
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

VERSION = "1.0.6"
UA = f"pretest/{VERSION} (authorized self-assessment)"
CDN = None   # set when the target sits behind a proxy; port findings then describe the edge
EXTRA_HEADERS: dict[str, str] = {}   # from --header, so authenticated areas can be probed
TIMEOUT = 12
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
FINDINGS: dict[str, dict] = {}


# ---------------------------------------------------------------- findings

def add(fid, sev, area, title, evidence="", why="", fix=""):
    if fid in FINDINGS:
        return
    FINDINGS[fid] = {
        "id": fid, "sev": sev, "area": area, "title": title,
        "evidence": _clip(evidence), "why": why, "fix": fix,
    }


def _clip(s, n=320):
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[:n] + " …"


# ---------------------------------------------------------------- http

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(url, method="GET", headers=None, timeout=TIMEOUT, follow=False, data=None):
    """Returns (status, headers|None, body bytes). Never raises."""
    req = urllib.request.Request(url, method=method, data=data)
    req.add_header("User-Agent", UA)
    for k, v in {**EXTRA_HEADERS, **(headers or {})}.items():
        req.add_header(k, v)
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.headers, r.read(400_000)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(400_000)
        except Exception:
            body = b""
        return e.code, e.headers, body
    except Exception as e:
        return None, None, repr(e).encode()


def H(headers, name):
    return headers.get(name) if headers else None


def _text(body):
    return body.decode("utf-8", "replace") if body else ""


# ---------------------------------------------------------------- transport

def http_checks(base, delay=0.2):
    url = base.rstrip("/") + "/"
    status, h, body = fetch(url)
    if status is None:
        add("unreachable", "info", "transport", "Ingen HTTP-anslutning",
            _text(body), fix="Kontrollera URL/scheme innan du tolkar resten av rapporten.")
        return None
    page = {"url": url, "status": status, "headers": h, "text": _text(body)}
    https = url.startswith("https://")
    global CDN
    if H(h, "cf-ray"):
        CDN = "Cloudflare"
    elif "cloudflare" in ((H(h, "server") or "").lower()):
        CDN = "Cloudflare"

    # --- redirect http -> https
    if not https:
        host = urllib.parse.urlsplit(url).netloc
        s2, _, _ = fetch(f"https://{host}/")
        if s2:
            loc = H(h, "location") or ""
            if not (300 <= status < 400 and loc.startswith("https://")):
                add("no-https-redirect", "high", "transport",
                    "HTTP svarar utan att skicka vidare till HTTPS",
                    f"GET {url} -> {status} {loc}", 
                    "All trafik i klartext går att avlyssna och ändra.",
                    "301 till https:// på allt utom ACME-utmaningar; sätt HSTS efteråt.")
        else:
            add("no-https", "critical", "transport", "HTTPS fungerar inte alls",
                f"https://{host}/ svarade inte", fix="Skaffa certifikat och terminera TLS.")

    # --- HSTS
    if https:
        hsts = H(h, "strict-transport-security")
        if not hsts:
            add("no-hsts", "medium", "transport", "HSTS saknas",
                f"strict-transport-security: {hsts!r}",
                "Utan HSTS kan första besöket kapas via nedgradering till HTTP.",
                "Strict-Transport-Security: max-age=31536000; includeSubDomains")
        else:
            m = re.search(r"max-age=(\d+)", hsts)
            if m and int(m.group(1)) < 15552000:
                add("weak-hsts", "low", "transport", "HSTS max-age är kort", hsts,
                    fix="Minst 15552000 (180 dagar), gärna 63072000 med preload.")

    # --- header hygiene
    csp = H(h, "content-security-policy")
    if not csp:
        add("no-csp", "low", "headers", "Ingen Content-Security-Policy",
            fix="Inför CSP som minskar effekten av XSS; börja i Report-Only, mät, skärp.")
    else:
        if "'unsafe-inline'" in csp and "script-src" in csp:
            add("csp-unsafe-inline", "low", "headers",
                "CSP tillåter 'unsafe-inline' i script-src", csp,
                "Ger nästan inget skydd mot XSS.", "Använd nonce/hash i stället för unsafe-inline.")
        if "report-only" in csp.lower():
            add("csp-report-only", "info", "headers", "CSP är bara Report-Only", csp,
                fix="Skärp tills rapporten är tom och sätt sedan skarpt läge.")

    if not H(h, "x-frame-options") and "frame-ancestors" not in (csp or ""):
        add("no-frame-protection", "medium", "headers", "Inget clickjacking-skydd",
            "varken X-Frame-Options eller CSP frame-ancestors",
            "Sidan kan bäddas in osynligt och användaren klickar på annat än de tror.",
            "CSP frame-ancestors 'none' (eller X-Frame-Options: DENY).")
    if (H(h, "x-content-type-options") or "").lower() != "nosniff":
        add("no-nosniff", "low", "headers", "X-Content-Type-Options saknas")
    if not H(h, "referrer-policy"):
        add("no-referrer-policy", "low", "headers", "Referrer-Policy saknas",
            fix="strict-origin-when-cross-origin.")
    if not H(h, "permissions-policy"):
        add("no-permissions-policy", "info", "headers", "Permissions-Policy saknas")

    for hdr in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        v = H(h, hdr)
        if v and re.search(r"\d+\.\d+", v):
            add(f"version-disclosure-{hdr}", "info", "headers",
                f"Version avslöjas i {hdr}", f"{hdr}: {v}",
                "Underlättar för angriparen att välja känd exploit.",
                "Ta bort eller normalisera headern.")

    # --- cookies
    raw_cookies = h.get_all("set-cookie") or [] if h else []
    for c in raw_cookies:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        missing = []
        if https and "secure" not in low:
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            add(f"cookie-flags-{name}", "medium", "cookies",
                f"Cookie '{name}' saknar {', '.join(missing)}", c,
                "Stjäls via XSS (HttpOnly), skickas i klartext (Secure) eller i CSRF (SameSite).",
                f"Set-Cookie: {name}=…; Secure; HttpOnly; SameSite=Lax"
                + ("; Prefixa med __Host- om cookien bara ska gälla värden." if https else ""))
        if https and name.startswith("__") and not name.startswith("__Host-") and not name.startswith("__Secure-"):
            add("cookie-bad-prefix", "low", "cookies", f"Cookie '{name}' använder reserverat prefix", c)

    # --- CORS
    origin = "https://pretest-cors.invalid"
    s2, h2, _ = fetch(url, headers={"Origin": origin})
    if h2:
        acao = H(h2, "access-control-allow-origin") or ""
        acac = (H(h2, "access-control-allow-credentials") or "").lower() == "true"
        if origin in acao and acac:
            add("cors-reflect-credentials", "critical", "cors",
                "CORS speglar godtyckligt Origin med credentials",
                f"ACAO: {acao} / ACAC: true",
                "Vilken sida som helst kan läsa inloggad användares data i webbläsaren.",
                "Allowlista av exakta origins; aldrig spegla Origin när credentials tillåts.")
        elif origin in acao:
            add("cors-reflect", "medium", "cors", "CORS speglar godtyckligt Origin",
                f"ACAO: {acao}", "Känsliga svar kan läsas av tredjepartssida.",
                "Allowlista av exakta origins.")
        elif acao == "*" and acac:
            add("cors-star-credentials", "high", "cors", "CORS: '*' tillsammans med credentials",
                f"ACAO: {acao} / ACAC: true", fix="Använd explicit origin, inte *.")

    # --- methods
    s3, h3, _ = fetch(url, method="OPTIONS")
    allow = (H(h3, "allow") or "") if h3 else ""
    if "TRACE" in allow.upper():
        add("trace-enabled", "low", "methods", "HTTP TRACE tillåtet", f"Allow: {allow}")

    # --- soft-404 baseline
    rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    bs, bh, bb = fetch(f"{url}pretest-{rnd}")
    page["baseline"] = (bs, len(bb or b""), H(bh, "content-type") or "")
    time.sleep(delay)

    exposed(base, page, delay)
    sourcemaps(base, page)
    return page


# ---------------------------------------------------------------- artifacts

PATHS = [
    (".git/config", "critical", r"\[core\]", "Publikt Git-repo — hela historiken kan laddas ner"),
    (".git/HEAD", "high", r"\Aref:\s", "Git-metadata exponerad"),
    (".env", "critical", r"(?m)^\s*[A-Z0-9_]{3,}\s*=", "Miljöfil med hemligheter"),
    (".env.local", "critical", r"(?m)^\s*[A-Z0-9_]{3,}\s*=", "Miljöfil med hemligheter"),
    (".env.production", "critical", r"(?m)^\s*[A-Z0-9_]{3,}\s*=", "Miljöfil med hemligheter"),
    ("config.php.bak", "critical", r"(?i)(password|db_)", "Källkodsbackup"),
    ("db.sql", "critical", r"(?i)(INSERT\s+INTO|CREATE\s+TABLE)", "Databasdump"),
    ("id_rsa", "critical", r"PRIVATE KEY", "Privat SSH-nyckel"),
    ("backup.zip", "high", None, "Backuparkiv nedladdningsbart"),
    ("actuator/env", "critical", r'"propertySources"', "Spring Actuator /env (hemligheter)"),
    ("actuator/heapdump", "critical", None, "Spring heapdump (minnesdump med tokens)"),
    ("actuator", "high", r'"_links"', "Spring Actuator exponerad"),
    ("debug/pprof/", "high", r"(?i)pprof", "Go pprof exponerad"),
    ("console", "high", r"(?i)(H2 Console|Werkzeug|Django administration)", "Utvecklingskonsol"),
    ("telescope", "high", r"(?i)telescope", "Laravel Telescope"),
    ("server-status", "medium", r"(?i)Apache Server Status", "Apache status-sida"),
    ("server-info", "medium", r"(?i)Apache Server Information", "Apache info-sida"),
    ("phpinfo.php", "medium", r"(?i)phpinfo", "phpinfo exponerad"),
    ("metrics", "medium", r"(?m)^#\s+(HELP|TYPE)\s", "Prometheus-metriker publika"),
    ("swagger.json", "medium", r'"(swagger|openapi)"', "API-specifikation"),
    ("openapi.json", "medium", r'"(swagger|openapi)"', "API-specifikation"),
    ("v3/api-docs", "medium", r'"(swagger|openapi)"', "API-specifikation"),
    ("graphql", "medium", r"(?i)(graphiql|__schema|introspection)", "GraphQL-endpoint utan skydd"),
    ("wp-json/wp/v2/users", "medium", r'"slug"', "WordPress-användarlista"),
    ("docker-compose.yml", "medium", r"(?m)^services:", "Driftkonfiguration"),
    ("xmlrpc.php", "low", r"(?i)XML-RPC server accepts POST", "xmlrpc.php (brute force-vektor)"),
    ("Dockerfile", "low", r"(?m)^FROM\s", "Byggfil"),
    ("package-lock.json", "low", r'"lockfileVersion"', "Beroendelista publikt"),
    (".DS_Store", "low", r"Bud1", "macOS-metadata (filnamnsläcka)"),
    ("robots.txt", "info", r"(?im)^(disallow|allow):", "robots.txt finns"),
    (".well-known/security.txt", "info", r"(?i)^contact:", "security.txt finns"),
]


PROBE_TIMEOUT = 8     # a healthy server answers a missing file in ms; a slow one may need seconds
PROBE_BUDGET = 90     # wall-clock ceiling for the whole artefact sweep, however slow the host is


def exposed(base, page, delay):
    bstatus, blen, bctype = page["baseline"]
    fails = 0
    seen = 0
    deadline = time.time() + PROBE_BUDGET
    for path, sev, sig, title in PATHS:
        if time.time() > deadline:
            add("probe-budget", "info", "artifacts",
                f"Tidsbudgeten tog slut efter {seen - 1} av {len(PATHS)} sökvägar",
                f"{PROBE_BUDGET}s totalt · värden svarar långsamt",
                "Resten är oprövade — inte rena.",
                "Höj med --delay 0 eller kör om från en snabbare nätväg.")
            return
        seen += 1
        url = base.rstrip("/") + "/" + path
        status, h, body = fetch(url, timeout=PROBE_TIMEOUT)
        time.sleep(delay)
        if status is None:
            fails += 1
            if fails >= 3:
                add("probe-aborted", "info", "artifacts",
                    f"Avbröt sökvägsskanningen: värden svarar inte ({seen} av {len(PATHS)} försökta)",
                    "tre anrop i rad nådde ingen server",
                    "Resten av artefaktkontrollerna är oprövade — inte rena.",
                    "Kör igen när värden svarar, eller kontrollera brandvägg/WAF.")
                return
            continue
        fails = 0
        text = _text(body)
        ctype = (H(h, "content-type") or "").lower()
        found = None
        if status == 200:
            if sig and re.search(sig, text[:4000]):
                found = text
            elif sig is None and ctype and "html" not in ctype and abs(len(body) - blen) > 64:
                found = f"{len(body)} bytes, {ctype}"
            elif sig is None and body[:4] == b"PK\x03\x04":
                found = "zip-magic"
        if found is None:
            if path == ".well-known/security.txt":
                add("no-security-txt", "info", "hygiene", "security.txt saknas",
                    fix="Publicera /.well-known/security.txt med Contact: så rapportörer når rätt person.")
            continue
        snippet = found if isinstance(found, str) and len(found) < 120 else text[:200]
        add(f"exposed-{path.replace('/', '-').strip('-')}", sev, "artifacts", title,
            f"GET {url} -> 200 · {_clip(snippet, 200)}",
            "Publik artefakt som avslöjar hemligheter, kod eller intern struktur.",
            "Ta bort filen från webbroten och rotera det som läckt.")
        if path == "robots.txt":
            dis = re.findall(r"(?im)^disallow:\s*(\S+)", text)
            hits = [d for d in dis if re.search(r"(?i)admin|backup|api|internal|private|debug|test", d)]
            if hits:
                add("robots-leak", "info", "artifacts",
                    "robots.txt pekar ut känsliga sökvägar", ", ".join(hits[:10]),
                    "En robots.txt är en karta för angriparen.",
                    "Skydda sökvägarna med auth, inte med robots.txt.")


def sourcemaps(base, page):
    srcs = re.findall(r'<script[^>]+src="([^"]+\.js[^"]*)"', page["text"])[:5]
    for src in srcs:
        url = urllib.parse.urljoin(page["url"], src)
        status, h, body = fetch(url + ".map", timeout=8)
        if status == 200 and body[:1] == b"{" and b'"sources"' in body[:5000]:
            add("sourcemaps-public", "medium", "artifacts", "Källkodskartor (source maps) publika",
                f"{url}.map", "Ger hela frontend-koden läsbar — logik, endpoints, ibland kommentarer.",
                "Publicera inte .map i produktion, eller skicka dem till felrapporteringstjänsten.")
            return


# ---------------------------------------------------------------- TLS

def _openssl(args, timeout=20):
    """(rc, stdout, stderr) from openssl s_client/x509. Never raises."""
    try:
        r = subprocess.run(["openssl", *args], input=b"", capture_output=True, timeout=timeout)
        return r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")
    except Exception as e:
        return 1, "", repr(e)


TLS_REASONS = [
    (r"verify error:num=18|self-signed certificate", "certifikatet är självsignerat"),
    (r"certificate has expired|verify error:num=10", "certifikatet har gått ut"),
    (r"verify error:num=62|hostname mismatch|does not match", "certifikatet matchar inte värdnamnet"),
    (r"verify error:num=2[01]|unable to get local issuer", "certifikatkedjan kan inte verifieras"),
    (r"read 0 bytes", "servern stängde anslutningen under handskakningen"),
    (r"alert handshake failure|sslv3 alert", "servern avvisade handskakningen med alert"),
    (r"no protocols available", "lokal OpenSSL kan inte protokollet"),
    (r"Connection refused", "anslutningen nekades"),
    (r"wrong version number", "porten talar inte TLS"),
]


def _tls_reason(out):
    """Human reason for a failed handshake, and the line it came from."""
    for pat, msg in TLS_REASONS:
        m = re.search(f"(?i).*({pat}).*", out)
        if m:
            return msg, m.group(0).strip()
    return "", ""


def _cipher(out):
    """Cipher from an s_client dump, or None ('Cipher is (NONE)' means it failed)."""
    m = re.search(r"Cipher(?: is |\s*:\s*)(\S+)", out)
    if not m or m.group(1).startswith("(NONE"):
        return None
    return m.group(1)


def tls_checks(host, port=443):
    args = ["s_client", "-connect", f"{host}:{port}", "-servername", host, "-showcerts"]
    rc, pem, err = _openssl(args, 25)
    if "BEGIN CERTIFICATE" not in pem:
        time.sleep(1.5)
        rc, pem, err = _openssl(args, 25)   # a dropped connection must not become a CRITICAL finding
    if "BEGIN CERTIFICATE" not in pem:
        reason, line = _tls_reason(pem + "\n" + err)
        add("tls-handshake", "critical", "tls",
            "TLS-handskakning misslyckas" + (f": {reason}" if reason else ""),
            _clip(line or (pem + err)[-200:]),
            "Ingen krypterad anslutning kan etableras — användaren möts av ett certifikatfel.",
            "Kontrollera certifikat, SNI och protokollversion.")
        return
    # openssl x509 reads the PEM from stdin only via file, so go through a temp file
    leaf = pem[pem.index("-----BEGIN CERTIFICATE-----"):]
    leaf = leaf[:leaf.index("-----END CERTIFICATE-----") + 25]
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(leaf + "\n")
        tmp = f.name
    try:
        out = subprocess.run(["openssl", "x509", "-noout", "-subject", "-issuer", "-enddate",
                              "-ext", "subjectAltName", "-in", tmp],
                             capture_output=True, timeout=15).stdout.decode()
    finally:
        os.unlink(tmp)

    end = re.search(r"notAfter=(.+)", out)
    if end:
        try:
            exp = datetime.strptime(end.group(1).strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            if days < 0:
                add("cert-expired", "critical", "tls", "Certifikatet har gått ut", f"notAfter {exp:%Y-%m-%d}")
            elif days < 14:
                add("cert-expiring", "high", "tls", f"Certifikatet går ut om {days} dagar", f"notAfter {exp:%Y-%m-%d}",
                    fix="Automatisera förnyelse (certbot/acme.sh) med larm.")
            elif days < 30:
                add("cert-expiring-soon", "medium", "tls", f"Certifikatet går ut om {days} dagar")
        except ValueError:
            pass

    verify = re.search(r"Verify return code:\s*(\d+)(?:\s*\(([^)]*)\))?", pem)
    if verify and verify.group(1) != "0":
        reason, _ = _tls_reason(pem)
        add("cert-untrusted", "high", "tls",
            "Certifikatet validerar inte" + (f": {reason}" if reason else ""),
            _clip(verify.group(0).strip() + (f" · {verify.group(2)}" if verify.group(2) else "")))

    proto = re.search(r"Protocol\s*:\s*(\S+)", pem)
    cipher = _cipher(pem)
    sans = re.search(r"DNS:([^\n]+)", out)
    if sans and re.search(r"(?i)(localhost|\.local|\.internal|\.lan|\b10\.|\b192\.168\.)", sans.group(1)):
        add("cert-internal-sans", "info", "tls", "Certifikatet avslöjar interna värdnamn",
            _clip(sans.group(1), 200), fix="Sanera SAN-listan.")

    untestable = []
    for opt, label in (("-tls1", "TLS 1.0"), ("-tls1_1", "TLS 1.1")):
        rc, out, err = _openssl(["s_client", "-connect", f"{host}:{port}", "-servername", host, opt], 12)
        c = _cipher(out + err)
        if rc == 0 and c:
            add(f"legacy-{label.replace(' ', '').replace('.', '')}", "medium", "tls",
                f"{label} accepteras", f"{label}: {c}",
                "Föråldrade protokoll med kända attacker (BEAST/POODLE).",
                "Tillåt bara TLS 1.2 och 1.3.")
        elif "no protocols" in err:
            untestable.append(label)
    if untestable:
        add("legacy-untestable", "info", "tls",
            f"{', '.join(untestable)} kan inte testas från den här maskinen",
            "lokal OpenSSL har protokollen avstängda",
            "Kör testssl.sh eller motsvarande från en maskin med äldre OpenSSL.",
            "Får inte tolkas som 'stöds inte' — det är overifierat.")
    if proto and cipher:
        add("tls-ok", "info", "tls", "TLS-konfiguration (referens)",
            f"{proto.group(1)} / {cipher}")
    else:
        add("tls-unparsed", "info", "tls", "TLS-sammanfattning kunde inte tolkas",
            _clip(pem[-200:]),
            fix="Kontrollera TLS manuellt (testssl.sh) — kontrollen kan ha misslyckats tyst.")


# ---------------------------------------------------------------- DNS

TAKEOVER = [
    r"\.s3\.amazonaws\.com$", r"\.s3-website[.-]", r"\.herokuapp\.com$", r"\.github\.io$",
    r"\.cloudfront\.net$", r"\.azurewebsites\.net$", r"\.cloudapp\.azure\.com$",
    r"\.vercel\.app$", r"\.netlify\.app$", r"\.trafficmanager\.net$", r"\.wordpress\.com$",
    r"\.readthedocs\.io$", r"\.surge\.sh$", r"\.bitbucket\.io$", r"\.ghost\.io$",
]
INTERESTING = r"(?i)^(dev|utv|stage|staging|test|qa|old|gammal|backup|admin|jenkins|gitlab|ci|grafana|kibana|phpmyadmin|internal|intern|vpn|ftp|db|api-internal)"


def doh(name, rtype, timeout=10):
    url = ("https://cloudflare-dns.com/dns-query?name="
           + urllib.parse.quote(name) + "&type=" + rtype)
    status, _, body = fetch(url, headers={"accept": "application/dns-json"}, timeout=timeout)
    if status != 200:
        return []
    try:
        return json.loads(body).get("Answer", [])
    except Exception:
        return []


def dns_checks(domain, delay=0.05):
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain or ""):
        return
    answers = doh(domain, "A") + doh(domain, "AAAA")
    if not answers:
        add("dns-no-a", "info", "dns", "Domänen svarar inte på A/AAAA via DoH", domain)
    txts = [a["data"].strip('"') for a in doh(domain, "TXT")]
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    if not spf:
        add("no-spf", "medium", "email", "Ingen SPF-post",
            f"TXT på {domain}: {txts[:5]}",
            "Vem som helst kan skicka e-post som ser ut att komma från domänen.",
            'v=spf1 include:<leverantör> -all')
    elif len(spf) > 1:
        add("multi-spf", "low", "email", "Flera SPF-poster", " | ".join(spf),
            "Ger oförutsägbart resultat (permerror).", "Slå ihop till en post.")
    elif not spf[0].rstrip().endswith("-all"):
        add("soft-spf", "low", "email", "SPF slutar inte med -all", spf[0])

    dmarc = [t for t in (a["data"].strip('"') for a in doh(f"_dmarc.{domain}", "TXT"))
             if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        add("no-dmarc", "medium", "email", "Ingen DMARC-post",
            fix="v=DMARC1; p=quarantine; rua=mailto:dmarc@domän — börja med p=none och läs rapporterna.")
    elif re.search(r"(?i)p\s*=\s*none", dmarc[0]):
        add("dmarc-none", "low", "email", "DMARC står på p=none", dmarc[0],
            "Ingen tillämpning — bara rapportering.", "Trappa upp till p=quarantine/reject.")

    dkim = []
    for sel in ("default", "google", "selector1", "selector2", "k1", "mail", "s1", "dkim"):
        if doh(f"{sel}._domainkey.{domain}", "TXT"):
            dkim.append(sel)
    if not dkim:
        add("dkim-unknown", "info", "email", "Ingen DKIM-selector hittades",
            "kontrollerat: default, google, selector1, selector2, k1, mail, s1, dkim",
            fix="Verifiera manuellt hos e-postleverantören; frånvaro kan vara falskt alarm.")
    else:
        add("dkim-ok", "info", "email", "DKIM-selectorer hittade", ", ".join(dkim))

    if not doh(domain, "CAA"):
        add("no-caa", "low", "dns", "Ingen CAA-post",
            fix='CAA 0 issue "letsencrypt.org" — hindrar felaktig utfärdare.')

    subs = _crtsh(domain)
    if subs:
        hits, takeovers = [], []
        for name in subs[:120]:
            cnames = [a["data"].rstrip(".") for a in doh(name, "CNAME")]
            if any(re.search(p, c.lower()) for c in cnames for p in TAKEOVER):
                takeovers.append(f"{name} -> {cnames[0]}")
            if INTERESTING.search(name.split(".")[0]) and (cnames or doh(name, "A")):
                hits.append(name)
            time.sleep(delay)
        if takeovers:
            add("takeover-risk", "high", "dns", "Möjlig subdomain takeover",
                " · ".join(takeovers[:8]),
                "Pekare mot molntjänst som kan vara oregistrerad — angriparen tar över namnet.",
                "Verifiera varje pekare manuellt och ta bort de som inte används.")
        if hits:
            add("exposed-subdomains", "medium", "dns",
                f"{len(hits)} icke-produktionssubdomäner svarar", ", ".join(hits[:12]),
                "Utvecklingsyta är oftast svagare skyddad än produktion och sällan med i ett pentest-scope.",
                "Stäng av eller auth-skydda; lägg dem i scopet när du beställer test.")
    return subs


def _crtsh(domain):
    status, _, body = fetch(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30)
    if status != 200:
        return []
    try:
        rows = json.loads(body)
    except Exception:
        return []
    names = set()
    for r in rows:
        for n in str(r.get("name_value", "")).split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n.endswith(domain) and n != domain:
                names.add(n)
    return sorted(names)


# ---------------------------------------------------------------- ports

PORTS = {
    21: ("high", "FTP"), 22: ("info", "SSH"), 25: ("low", "SMTP"),
    3306: ("high", "MySQL"), 5432: ("high", "PostgreSQL"), 6379: ("high", "Redis"),
    9200: ("high", "Elasticsearch"), 11211: ("high", "Memcached"),
    27017: ("high", "MongoDB"), 2375: ("critical", "Docker API (okrypterad, utan auth)"),
    2376: ("medium", "Docker API"), 5601: ("medium", "Kibana"), 3000: ("low", "dev-server"),
    5000: ("low", "dev-server"), 8000: ("low", "dev-server"), 8080: ("low", "HTTP alt"),
    8443: ("info", "HTTPS alt"), 8888: ("low", "Jupyter"), 9090: ("low", "Prometheus"),
}


def _open(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def port_checks(host, ports=None):
    ports = ports or sorted(PORTS)
    with ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(lambda p: (p, _open(host, p)), ports))
    openp = [p for p, ok in results if ok]
    for p in openp:
        sev, label = PORTS.get(p, ("info", "okänt"))
        if CDN:
            add(f"port-{p}", "info", "ports", f"Port {p} öppen ({label}) — på {CDN}s edge",
                f"{host}:{p} accepterar anslutning",
                f"Värdnamnet pekar på {CDN}, så porten tillhör deras nät — inte din server.",
                "Verifiera mot origin-IP om du vill veta vad som faktiskt lyssnar hemma.")
            continue
        if sev in ("info",):
            add(f"port-{p}", "info", "ports", f"Port {p} öppen ({label})")
        else:
            add(f"port-{p}", sev, "ports", f"Port {p} öppen ({label})",
                f"{host}:{p} accepterar anslutning",
                "Tjänsten ska oftast bara nås internt." if p not in (21,) else "Klartextprotokoll.",
                "Brandvägg/security group: allowlista, eller bind till localhost.")


# ---------------------------------------------------------------- repo

SECRET_PATTERNS = [
    ("aws-key", r"AKIA[0-9A-Z]{16}"),
    ("private-key", r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ("stripe-live", r"sk_live_[0-9a-zA-Z]{16,}"),
    ("github-token", r"gh[pousr]_[A-Za-z0-9]{20,}"),
    ("slack-token", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ("google-api-key", r"AIza[0-9A-Za-z_-]{35}"),
    ("jwt-app-secret", r"(?i)(app_?key|secret_?key|jwt_?secret)\s*[:=]\s*['\"][^'\"]{12,}['\"]"),
]
SKIP_DIRS = {".git", "node_modules", "target", "dist", "build", ".venv", "venv", "__pycache__",
             ".next", "vendor", ".cache", "coverage"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".woff",
            ".woff2", ".ttf", ".mp4", ".mp3", ".wasm", ".so", ".dylib", ".exe", ".bin", ".lock"}


def repo_checks(path):
    root = os.path.abspath(os.path.expanduser(path))
    if not os.path.isdir(root):
        add("repo-missing", "info", "repo", "Repo-sökvägen finns inte", root)
        return
    hits, seen, files = [], 0, 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in SKIP_EXT:
                continue
            fp = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(fp) > 512_000:
                    continue
                with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue
            files += 1
            for name, pat in SECRET_PATTERNS:
                m = re.search(pat, content)
                if m:
                    rel = os.path.relpath(fp, root)
                    if (rel, name) not in seen:
                        seen.add((rel, name))
                        hits.append(f"{rel}: {name}")
            if files > 4000:
                break
        if files > 4000:
            break
    if hits:
        add("repo-secrets", "critical", "repo", f"{len(hits)} misstänkta hemligheter i källkoden",
            " · ".join(hits[:10]) + (" …" if len(hits) > 10 else ""),
            "Hemligheter i git-historiken läcker även om filen raderas.",
            "Rotera nycklarna, rensa historiken (git filter-repo), flytta till miljövariabler.")

    gi = os.path.join(root, ".gitignore")
    if not os.path.exists(gi):
        add("no-gitignore", "low", "repo", ".gitignore saknas")
    else:
        with open(gi, encoding="utf-8", errors="ignore") as f:
            body = f.read()
        for want in (".env", "node_modules", "dist"):
            if want not in body and want != "dist":
                add(f"gitignore-{want.strip('.')}", "low", "repo", f".gitignore täcker inte {want}")

    sca(root)


def sca(root):
    """Run whatever dependency auditor is installed. Unparsed output is fine —
    a pentester cannot find these at all, so 'go look' is the useful result."""
    jobs = [
        ("package-lock.json", ["npm", "audit", "--json", "--omit=dev"]),
        ("requirements.txt", ["pip-audit", "-f", "json"]),
        ("pyproject.toml", ["pip-audit", "-f", "json"]),
        ("Cargo.lock", ["cargo", "audit", "--json"]),
        ("composer.lock", ["composer", "audit", "--format=json"]),
    ]
    done = set()
    for manifest, cmd in jobs:
        if not os.path.exists(os.path.join(root, manifest)) or cmd[0] in done:
            continue
        if not _which(cmd[0]):
            add(f"sca-missing-{cmd[0]}", "info", "deps",
                f"{cmd[0]} finns inte installerat — beroendesårbarheter ej kontrollerade",
                f"manifest: {manifest}", fix=f"Installera {cmd[0]} eller kör i CI.")
            continue
        done.add(cmd[0])
        try:
            r = subprocess.run(cmd, cwd=root, capture_output=True, timeout=180,
                               text=True, errors="replace")
        except Exception as e:
            add(f"sca-fail-{cmd[0]}", "info", "deps", f"{cmd[0]} kunde inte köras", repr(e))
            continue
        if r.returncode != 0:
            out = (r.stdout or "") + (r.stderr or "")
            nums = re.search(r'"(critical|high|moderate|low)"\s*:\s*(\d+)', out)
            add(f"sca-{cmd[0]}", "high", "deps", f"Kända sårbarheter i beroenden ({cmd[0]})",
                _clip(out.strip()[-300:]) if out.strip() else f"exit {r.returncode}",
                "Pentestaren hittar dem inte (svart låda), men en angripare kan slå upp dem.",
                "Uppgradera eller byt paket; lägg `npm audit --audit-level=high` i CI.")
        else:
            add(f"sca-ok-{cmd[0]}", "info", "deps", f"{cmd[0]}: inga kända sårbarheter")


def _which(binary):
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, binary)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


# ---------------------------------------------------------------- scan

def scan(base, domain=None, repo=None, portscan=True, dns=True, delay=0.2):
    dest = urllib.parse.urlsplit(base)
    host = dest.hostname
    if not host:
        add("bad-url", "info", "transport", "Ogiltig URL", base)
        return
    page = http_checks(base, delay)
    if dest.scheme == "https":
        tls_checks(host, dest.port or 443)
    if dns:
        dns_checks(domain or host, delay=min(delay, 0.1))
    if portscan:
        port_checks(host)
    if repo:
        repo_checks(repo)
    return page


COVERAGE = """\
Vad verktyget INTE kan hitta (det du betalar en pentestare för):
  · Auktorisering och IDOR — byta id i en URL, se andras data, rolleskalering
  · Affärslogik — hoppa över betalsteg, negativa belopp, race conditions, dubbel uttag
  · Autentisering/session — token-livstid, fixation, MFA-bypass, lösenordsåterställning
  · Injicering som kräver kontext — SQLi/NoSQL/SSTI/XXE/SSRF i applikationens egna parametrar
  · Filuppladdning, deserialisering, mallinjicering
  · Kedjor: låg + låg = admin
  · Försvararsidan — loggas och larmas ett angrepp?
Använd det här som underlag i scopet: skriv explicit att ovanstående ska testas,
och bifoga den här rapporten så slipper de lägga tid på headers och /.env."""


def report(target, as_json=False):
    items = sorted(FINDINGS.values(), key=lambda f: (SEV_ORDER[f["sev"]], f["area"]))
    counts = {s: sum(1 for f in items if f["sev"] == s) for s in SEV_ORDER}
    if as_json:
        return json.dumps({
            "tool": f"pretest/{VERSION}",
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "target": target, "counts": counts, "findings": items,
        }, indent=2, ensure_ascii=False)

    out = [f"pretest {VERSION} — {datetime.now().astimezone():%Y-%m-%d %H:%M %Z}",
           f"Mål: {target}",
           " ".join(f"{s}:{counts[s]}" for s in SEV_ORDER if counts[s]), ""]
    for f in items:
        if f["sev"] == "info" and f["id"].endswith("-ok"):
            continue
        out.append(f"[{f['sev'].upper():8}] {f['area']:10} {f['title']}")
        if f["evidence"]:
            out.append(f"           bevis: {f['evidence']}")
        if f["why"]:
            out.append(f"           varför: {f['why']}")
        if f["fix"]:
            out.append(f"           åtgärd: {f['fix']}")
    out += ["", COVERAGE]
    return "\n".join(out)


# ---------------------------------------------------------------- self-test

def self_test():
    import http.server
    import threading

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            p = self.path.rstrip("/") or "/"
            if p in ("/", "/index.html"):
                body = b"<html><body><script src=\"/app.js\"></script>hej</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Server", "TestSrv/0.9")
                self.send_header("Set-Cookie", "sid=abc123; Path=/")
            elif p == "/.env":
                body = b"DB_PASSWORD=hunter2\nSECRET_KEY=abcdef\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
            elif p == "/.git/config":
                body = b"[core]\n\trepositoryformatversion = 0\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
            elif p == "/app.js.map":
                body = b'{"version":3,"sources":["a.ts"]}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
            else:
                body = b"nope"
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
            if self.headers.get("Origin"):
                self.send_header("Access-Control-Allow-Origin", self.headers["Origin"])
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header("Allow", "GET, OPTIONS, TRACE")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    class Quiet(http.server.ThreadingHTTPServer):
        def handle_error(self, request, client_address):
            pass    # the scanner closes early connections on purpose; the traceback is noise

    srv = Quiet(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        scan(f"http://127.0.0.1:{port}", portscan=False, dns=False, delay=0)
    finally:
        srv.shutdown()

    expect = {"no-https", "exposed-.env", "exposed-.git-config",
              "cors-reflect-credentials", "cookie-flags-sid", "sourcemaps-public",
              "no-nosniff", "no-frame-protection", "trace-enabled"}
    got = set(FINDINGS)
    missing = expect - got
    print(f"self-test: {len(got)} fynd, {len(expect)} förväntade")
    if missing:
        print("SAKNAS:", ", ".join(sorted(missing)))
        return 1
    print("OK")
    return 0


# ---------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(description="Automatiserad förkontroll inför penetrationstest.")
    ap.add_argument("--url", help="Bas-URL, t.ex. https://example.se")
    ap.add_argument("--domain", help="Domän för DNS/e-postkontroller (default: värdnamnet i --url)")
    ap.add_argument("--repo", help="Sökväg till källkoden för hemlighets- och beroendeskamning")
    ap.add_argument("--json", metavar="FIL", help="Skriv rapport som JSON")
    ap.add_argument("--no-portscan", action="store_true", help="Hoppa över TCP-porttest")
    ap.add_argument("--no-dns", action="store_true", help="Hoppa över DNS/e-postkontroller")
    ap.add_argument("--delay", type=float, default=0.2, help="Sekunder mellan HTTP-anrop (default 0.2)")
    ap.add_argument("-H", "--header", action="append", default=[], metavar="'Namn: värde'",
                    help="Extra header på varje anrop, t.ex. -H 'Cookie: session=…' för inloggat läge")
    ap.add_argument("--fail-on", choices=list(SEV_ORDER), help="Exit 1 om fynd på denna nivå eller allvarligare")
    ap.add_argument("--self-test", action="store_true", help="Kör inbyggt test mot lokal fixtureserver")
    ap.add_argument("--version", action="version", version=f"pretest {VERSION}")
    args = ap.parse_args(argv)

    for raw in args.header:
        name, _, value = raw.partition(":")
        if not name.strip() or not value.strip():
            ap.error(f"--header måste vara 'Namn: värde', fick {raw!r}")
        EXTRA_HEADERS[name.strip()] = value.strip()

    if args.self_test:
        return self_test()
    if not args.url:
        ap.error("--url krävs (eller --self-test)")

    base = args.url if "://" in args.url else "https://" + args.url
    print(f"# pretest {VERSION} mot {base} — endast mot system du äger eller har tillstånd att testa",
          file=sys.stderr)
    scan(base, args.domain, args.repo, not args.no_portscan, not args.no_dns, args.delay)
    print(report(base, as_json=False))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(report(base, as_json=True))
        print(f"\nJSON: {args.json}", file=sys.stderr)

    if args.fail_on:
        limit = SEV_ORDER[args.fail_on]
        if any(SEV_ORDER[f["sev"]] <= limit for f in FINDINGS.values()):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
