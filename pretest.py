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
import base64
import hashlib
import hmac
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

VERSION = "1.3.0"
UA = f"pretest/{VERSION} (authorized self-assessment)"
CDN = None   # set when the target sits behind a proxy; port findings then describe the edge
EXTRA_HEADERS: dict[str, str] = {}   # from --header, so authenticated areas can be probed
TARGET_ORIGIN = None   # scheme+host+port; credentials go here and nowhere else
TIMEOUT = 12
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
FINDINGS: dict[str, dict] = {}


# ---------------------------------------------------------------- findings

def add(fid, sev, area, title, evidence="", why="", fix=""):
    fid = _redact(fid)          # the key is serialised too, so it masks like everything else
    if fid in FINDINGS:
        return
    FINDINGS[fid] = {
        "id": fid, "sev": sev, "area": _redact(area),
        "title": _redact(title),
        "evidence": _clip(_redact(evidence)),
        "why": _redact(why),
        "fix": _redact(fix),
    }


def _redact(text):
    """One chokepoint: every serialised field passes through here.

    A secret no pattern recognises (an opaque token in an HTML comment) is still caught by the
    last rule: any 20+ character run that contains a digit. Doc examples ("max-age=31536000",
    "X-Permitted-Cross-Domain-Policies") contain no digits and survive.
    """
    s = str(text)
    for _, _, pat in WEB_SECRETS:
        s = re.sub(pat, lambda m: _mask(m.group(0)), s)
    s = JWT_RE.sub(lambda m: _mask(m.group(0)), s)
    s = re.sub(r"(?i)\b([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE_KEY)[A-Z0-9_]*)"
               r"(\s*[=:]\s*)\S+", r"\1\2…", s)
    s = re.sub(r"(?i)\b(cookie|set-cookie)\s*:\s*\S+", r"\1: …", s)
    s = re.sub(r"\b([\w.-]+=)[^;\s]{12,}", r"\1…", s)      # long cookie/token values in a header dump
    s = re.sub(r"://[^/\s@]+@", "://…@", s)                  # https://user:pass@host
    s = re.sub(r"\b(?=[A-Za-z0-9_+/=-]{20,}\b)(?=[A-Za-z0-9_+/=-]*\d)[A-Za-z0-9_+/=-]+",
               lambda m: _mask(m.group(0)), s)
    return s


def _clip(s, n=320):
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[:n] + " …"


# ---------------------------------------------------------------- http

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _origin(url):
    """(scheme, host, port). Raises ValueError on a port outside 0-65535, which callers guard."""
    s = urllib.parse.urlsplit(url)
    port = s.port          # raises ValueError outside 0-65535: never equate that with 443/80
    if port is None:
        port = 443 if s.scheme == "https" else 80
    return (s.scheme, (s.hostname or "").lower(), port)


def fetch(url, method="GET", headers=None, timeout=TIMEOUT, data=None, auth=True):
    """Returns (status, headers|None, body bytes). Never raises."""
    req = urllib.request.Request(url, method=method, data=data)
    req.add_header("User-Agent", UA)
    same_origin = False
    if auth and TARGET_ORIGIN:
        try:
            same_origin = _origin(url) == TARGET_ORIGIN
        except ValueError:
            same_origin = False
    if same_origin:
        for k, v in EXTRA_HEADERS.items():
            req.add_header(k, v)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    opener = urllib.request.build_opener(_NoRedirect)   # a redirect is data, never a place to follow
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

def https_entry(host, http_status, http_url, http_headers, port=443):
    """What the visitor meets on https://<host>/ when the site was reached over http."""
    s2, _, b2 = fetch(f"https://{host}/" if port == 443 else f"https://{host}:{port}/")
    if s2:
        loc = H(http_headers, "location") or ""
        if not (300 <= http_status < 400 and loc.startswith("https://")):
            add("no-https-redirect", "high", "transport",
                "HTTP svarar utan att skicka vidare till HTTPS",
                f"GET {http_url} -> {http_status} {loc}",
                "All trafik i klartext går att avlyssna och ändra.",
                "301 till https:// på allt utom ACME-utmaningar; sätt HSTS efteråt.")
        return
    reason, line = _tls_reason(_text(b2) if b2 else "")
    if reason and re.search(r"certifikat|kedjan|värdnamn", reason):
        add("https-cert-broken", "high", "tls",
            f"HTTPS går inte att använda: {reason}",
            _clip(line or _text(b2)),
            "Besökaren möts av en certifikatvarning och kan inte lita på anslutningen.",
            "Kontrollera certifikatet och att rätt kedja serveras på rätt port.")
    elif reason:
        add("no-https", "high", "transport", f"HTTPS fungerar inte: {reason}",
            _clip(line or _text(b2)),
            fix="Kontrollera TLS-termineringen på rätt port.")
    else:
        add("https-unreachable", "info", "transport",
            "HTTPS nåddes inte — orsaken är okänd", _clip(_text(b2) or "inget svar"),
            "Kan vara brandvägg, port eller tillfälligt nätfel.",
            "Verifiera TLS manuellt innan detta tolkas som saknad kryptering.")


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

    # --- redirect http -> https, only meaningful at the standard entry point
    if not https:
        port = (TARGET_ORIGIN or ("http", "", 80))[2]
        if port != 80:
            add("https-standard-port-unchecked", "info", "transport",
                "HTTPS på standardporten är inte prövad",
                f"målet ligger på port {port} — sajtens vanliga ingång kan vara en annan",
                "Kör mot https://<värd>/ för att pröva det besökaren faktiskt möter.")
        else:
            https_entry(urllib.parse.urlsplit(url).hostname or "", status, url, h)

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
    for hdr, fid, sev in (("cross-origin-opener-policy", "no-coop", "info"),
                          ("cross-origin-resource-policy", "no-corp", "info"),
                          ("x-permitted-cross-domain-policies", "no-xpcdp", "low")):
        if not H(h, hdr):
            add(fid, sev, "headers", f"{hdr} saknas",
                fix="Sätt same-origin (COOP/CORP) och none (X-Permitted-Cross-Domain-Policies).")

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
        parts = [p.strip() for p in c.split(";")]
        name = parts[0].split("=", 1)[0].strip()
        attrs = {p.split("=", 1)[0].strip().lower() for p in parts[1:] if p}
        missing = []
        if https and "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if "samesite" not in attrs:
            missing.append("SameSite")
        if missing:
            sessionish = bool(re.search(r"(?i)sess|sid|auth|token|jwt|login|user|remember", name))
            add(f"cookie-flags-{name}", "medium" if sessionish else "low", "cookies",
                f"Cookie '{name}' saknar {', '.join(missing)}", c,
                ("Ser ut som en sessionscookie: " if sessionish else "Ser inte ut som en sessionscookie, men: ")
                + f"utan {', '.join(missing)} kan den läsas av skript, skickas i klartext "
                  "eller följa med i en CSRF-förfrågan.",
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
        matched = [o.strip() for o in acao.split(",")] if acao else []
        if origin in matched and acac:
            add("cors-reflect-credentials", "high", "cors",
                "CORS speglar godtyckligt Origin med credentials (konfigurationsfel)",
                f"ACAO: {acao} / ACAC: true",
                "Konfigurationen tillåter vilken sajt som helst att läsa svar med credentials. "
                "Om ett sådant svar innehåller användardata är det en direkt läcka — det prövar "
                "verktyget inte.",
                "Allowlista av exakta origins; aldrig spegla Origin när credentials tillåts. "
                "Verifiera manuellt vilket känsligt svar som faktiskt returneras.")
        elif origin in matched:
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
    content_audit(page)
    js_analysis(base, page)
    cloud_storage(page)
    jwt_checks(page)
    host_header(base)
    error_pages(base)
    methods_scan(base)
    xdomain(base)
    cached_auth_response(page)
    active_auth(base, page)
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
    _, blen, _ = page["baseline"]
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
            add("sourcemaps-public", "low", "artifacts", "Källkodskartor (source maps) publika",
                f"{url}.map", "Ger hela frontend-koden läsbar — logik, endpoints, ibland kommentarer.",
                "Publicera inte .map i produktion, eller skicka dem till felrapporteringstjänsten.")
            return


# ---------------------------------------------------------------- content, bundles, tokens

def _mask(secret):
    """Never put a live secret in a report or in a commit."""
    s = str(secret)
    return f"{s[:4]}…{s[-4:]} ({len(s)} tecken)" if len(s) > 12 else "…"


WEB_SECRETS = [
    ("aws-nyckel", "critical", r"AKIA[0-9A-Z]{16}"),
    ("privat-nyckel", "critical", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ("stripe-live", "critical", r"sk_live_[0-9a-zA-Z]{16,}"),
    ("github-token", "high", r"gh[pousr]_[A-Za-z0-9]{20,}"),
    ("slack-token", "high", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ("google-api-nyckel", "high", r"AIza[0-9A-Za-z_-]{35}"),
    ("hemlighet-i-kod", "medium",
     r"(?i)(?:api[_-]?key|secret|token|password|passwd)\s*[:=]\s*[\"'][^\"'\s]{12,}[\"']"),
]
INTERNAL_HOST = re.compile(r"https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+"
                           r"|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|[\w.-]+\.(?:internal|local|lan)\b)")


def _scan_secrets(text, source):
    hits = []
    for label, sev, pat in WEB_SECRETS:
        for m in re.finditer(pat, text):
            hits.append((label, sev, m.group(0), source))
            if len(hits) >= 6:
                return hits
    return hits


def js_analysis(base, page):
    """The bundles a browser downloads are public source code. Read them."""
    srcs = re.findall(r'<script[^>]+src="([^"]+\.js[^"]*)"', page["text"])
    inline = re.findall(r"<script[^>]*>(.{40,}?)</script>", page["text"], re.S)
    bodies = [("inline <script>", t) for t in inline[:3]]
    missed = 0
    for src in srcs[:6]:
        url = urllib.parse.urljoin(page["url"], src)
        status, _, body = fetch(url, timeout=PROBE_TIMEOUT, auth=False)
        if status == 200 and body:
            bodies.append((src, _text(body)))
        else:
            missed += 1
        time.sleep(0.1)
    if missed:
        add("js-partial", "info", "content",
            f"{missed} skript kunde inte hämtas",
            "resten av frontendkoden är oprövad — inte ren")
    if not bodies and missed:
        return          # js-partial already reports the bundles as unproven
    if not bodies:
        add("js-none", "info", "content", "Inga skript att genomsöka",
            "0 externa <script src> och inga inline-block över 40 tecken",
            "Hemligheter i frontendkoden är alltså oprövade — inte frånvarande.",
            "Kör mot den sida som faktiskt laddar applikationens bundles.")
        return

    page["js_bodies"] = [t for _, t in bodies]     # jwt_checks reads tokens from here too
    hits, internal = [], set()
    for name, text in bodies:
        hits += _scan_secrets(text, name)
        for m in INTERNAL_HOST.finditer(text):
            internal.add(m.group(0).rstrip('"\''))

    if hits:
        seen = set()
        ev = []
        for label, sev, value, src in hits:
            key = (label, value)
            if key in seen:
                continue
            seen.add(key)
            ev.append(f"{label} i {src}: {_mask(value)}")
        worst = "critical" if any(h[1] == "critical" for h in hits) else (
                "high" if any(h[1] == "high" for h in hits) else "medium")
        add("js-secrets", worst, "content",
            f"Hemligheter i publika JavaScript-filer ({len(seen)} st)", " · ".join(ev[:6]),
            "Bundlarna är läsbara för vem som helst. Nycklar i dem används direkt av en angripare.",
            "Flytta hemligheten till servern, rotera den, och lägg en kontroll i CI som stoppar nästa.")

    for name, text in bodies:
        todos = re.findall(r"(?:TODO|FIXME|HACK|XXX)[: ]([^\n*/]{6,80})", text)
        if todos:
            add("js-todo", "info", "content", f"Utvecklingsanteckningar i publika skript ({len(todos)})",
                " · ".join(t.strip()[:60] for t in todos[:3]),
                "Avslöjar interna vägar, namn och ibland lösenord som glömts kvar.",
                "Strippa kommentarer i produktionsbygget.")

    if internal:
        add("js-internal-hosts", "medium", "content", "Interna värdnamn i publika skript",
            ", ".join(sorted(internal)[:6]),
            "Ger en angripare en karta till de system som inte ska vara nåbara utifrån.",
            "Byt mot publika endpoints i produktionsbygget.")


def cloud_storage(page):
    """A bucket URL on the page is the page's claim about where data lives."""
    found = set(re.findall(
        r"https?://[\w.-]*(?:s3[.-][\w.-]*amazonaws\.com[\w/.-]*|storage\.googleapis\.com/[\w.-]+"
        r"|blob\.core\.windows\.net/[\w$-]+|[\w.-]+\.s3\.amazonaws\.com[\w/.-]*)",
        page["text"]))
    if not found:
        return
    public, private = [], []
    for url in list(found)[:4]:
        status, _, body = fetch(url, timeout=PROBE_TIMEOUT)
        time.sleep(0.15)
        if status == 200 and b"<ListBucketResult" in body:
            public.append(url)
        elif status in (403, 401):
            private.append(url)
    if public:
        add("cloud-bucket-public", "critical", "content", "Publik molnlagring (listning öppen)",
            ", ".join(public[:4]),
            "Allt i bucketen kan listas och laddas ner — ofta backuper, bilder och exportfiler.",
            "Stäng publik listning och sätt bucket policy per objekt.")
    elif private:
        add("cloud-bucket-private", "info", "content", "Molnlagring refererad från sidan",
            ", ".join(private[:4]) + " (403 — inte listbar, vilket är rätt)",
            fix="Bekräfta att objektens egna ACL:er inte är öppna.")


JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,}")
WEAK_JWT_SECRETS = ["secret", "password", "changeme", "secretkey", "jwtsecret", "supersecret",
                    "your-256-bit-secret", "test", "dev", "admin", "key", "1234", "s3cr3t"]


def _b64json(seg):
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg))


def jwt_checks(page):
    """A token handed to the browser is a claim about authority — read its header."""
    tokens = set(JWT_RE.findall(page["text"]))
    for body in page.get("js_bodies", []):
        tokens |= set(JWT_RE.findall(body))
    for value in EXTRA_HEADERS.values():
        tokens |= set(JWT_RE.findall(value))
    for c in (page["headers"].get_all("set-cookie") or []) if page["headers"] else []:
        tokens |= set(JWT_RE.findall(c))
    if not tokens:
        return

    for tok in list(tokens)[:6]:      # varje token har egna grenar; tre räckte inte
        parts = tok.split(".")
        try:
            head = _b64json(parts[0])
            payload = _b64json(parts[1]) if len(parts) > 1 and parts[1] else {}
        except Exception:
            add("jwt-unparsed", "info", "tokens", "JWT hittad men kunde inte avkodas", _mask(tok))
            continue
        alg = str(head.get("alg", "")).lower()
        if alg == "none":
            add("jwt-alg-none", "medium", "tokens",
                "JWT med alg=none i omlopp (serverns acceptans är inte prövad)",
                f"header: {json.dumps(head)[:120]}",
                "En osignerad token får aldrig godtas. Verktyget ser bara att en sådan token "
                "når klienten — om backend accepterar den måste prövas manuellt.",
                "Neka alg=none i verifieringen med en allowlista av tillåtna algoritmer, "
                "och verifiera sedan med ett eget anrop att en osignerad token avvisas.")
        if "exp" not in payload:
            add("jwt-no-exp", "medium", "tokens", "JWT saknar utgångstid (exp)",
                f"claims: {', '.join(sorted(payload)[:8])}",
                "En stulen token gäller för evigt.",
                "Sätt kort exp och förnya via refresh-token.")
        if alg.startswith("hs") and len(parts) == 3:
            signing_input = f"{parts[0]}.{parts[1]}".encode()
            for secret in WEAK_JWT_SECRETS:
                digest = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
                if base64.urlsafe_b64encode(digest).rstrip(b"=").decode() == parts[2].rstrip("="):
                    add("jwt-weak-secret", "high", "tokens",
                        "JWT signerad med en gissningsbar hemlighet "
                        "(backendens acceptans är inte prövad)",
                        f"signaturen matchar en nyckel ur en kort gissningslista "
                        f"('{secret[0]}…{secret[-1]}', {len(secret)} tecken) — matematiskt verifierat",
                        "Signaturen går att återskapa med en nyckel från en kort lista. Om backend "
                        "accepterar en sådan token kan alla konton kapas — det prövar verktyget inte.",
                        "Rotera hemligheten till 256 bitars slump och ogiltigför samtliga tokens.")
                    break
        kid = str(head.get("kid", ""))
        if kid and re.search(r"[:/\\]|\.\.", kid):
            add("jwt-kid-injection", "high", "tokens", "JWT kid innehåller sökvägstecken",
                f"kid: {_clip(kid, 80)}",
                "Om servern slår upp nyckeln via kid kan den pekas mot en fil angriparen styr.",
                "Behandla kid som ett id i en allowlista, aldrig som en sökväg.")


def content_audit(page):
    text = page["text"]
    comments = re.findall(r"<!--(.*?)-->", text, re.S)
    interesting = [c.strip() for c in comments
                   if re.search(r"(?i)todo|fixme|password|passwd|api[_-]?key|secret|internal|"
                                r"debug|staging|dev\.|test\.|lösen", c)]
    if interesting:
        add("html-comments", "info", "content", "Kommentarer i HTML avslöjar intern information",
            " · ".join(_clip(c, 90) for c in interesting[:3]),
            "Ofta det snabbaste sättet att hitta interna system och glömda funktioner.",
            "Strippa kommentarer i produktionsrenderingen.")

    hidden = re.findall(r'<input[^>]+type=["\']hidden["\'][^>]*>', text, re.I)
    risky = [h for h in hidden if re.search(r"(?i)admin|role|debug|token|price|amount|user_?id", h)]
    if risky:
        add("hidden-fields", "low", "content", "Känsliga fält skickas som hidden",
            " · ".join(_clip(h, 90) for h in risky[:3]),
            "Hidden-fält är klientstyrda: värdet kan ändras av användaren.",
            "Verifiera auktoritet på servern, aldrig via ett dolt fält.")

    blanks = re.findall(r'<a\b[^>]*target=["\']_blank["\'][^>]*>', text, re.I)
    unsafe = [b for b in blanks if "noopener" not in b.lower() and "noreferrer" not in b.lower()]
    if unsafe:
        add("noopener-missing", "low", "content",
            f"{len(unsafe)} länk(ar) med target=_blank saknar rel=noopener",
            _clip(unsafe[0], 100),
            "Den öppnade sidan får tillgång till window.opener och kan styra om fliken.",
            'rel="noopener noreferrer" på varje target="_blank".')


def host_header(base):
    """Password-reset poisoning starts here: does the app believe a header?"""
    probe = "pretest.invalid"
    status, _, body = fetch(base.rstrip("/") + "/", headers={"X-Forwarded-Host": probe})
    if status and probe in _text(body):
        add("host-header-injection", "high", "content",
            "X-Forwarded-Host ekar in i sidans innehåll",
            f"X-Forwarded-Host: {probe} syntes i svaret",
            "Byggs länkar eller återställningsadresser av headern kan angriparen styra dem.",
            "Använd en fast konfigurerad bas-URL, eller en allowlista av värdnamn.")


ERROR_MARKERS = [
    (r"Traceback \(most recent call last\)", "Python-traceback"),
    (r"at [\w.$]+\([\w.]+\.java:\d+\)", "Java-stacktrace"),
    (r"(?i)stack trace:|#0\s+/", "PHP-stacktrace"),
    (r"(?i)(Django|Werkzeug) (debug|Debug)", "Django/Werkzeug debug"),
    (r"Whoops! There was an error", "Laravel Whoops"),
    (r"SQLSTATE\[", "databasfel (SQLSTATE)"),
    (r"(?i)you have an error in your sql syntax", "SQL-felmeddelande"),
]


def error_pages(base):
    """Ask for something that cannot exist and read the apology."""
    rnd = "".join(random.choices(string.ascii_lowercase, k=8))
    for path in (f"pretest-err-{rnd}", f"pretest-err-{rnd}'\"<>", f"pretest-err-{rnd}%00"):
        status, _, body = fetch(base.rstrip("/") + "/" + urllib.parse.quote(path, safe="%"),
                                timeout=PROBE_TIMEOUT)
        time.sleep(0.15)
        if status is None or status < 400:
            continue      # a 200 can quote a traceback in documentation without being a leak
        text = _text(body)
        for pat, label in ERROR_MARKERS:
            m = re.search(pat, text)
            if m:
                detailed = bool(re.search(r'(File "|at [\w.$]+\(|\.java:\d+|#0\s+/|/var/www|'
                                          r'/[\w.-]+/[\w.-]+\.(php|py|rb|js):\d+)', text))
                add(f"error-leak-{label.split()[0].lower()}", "medium" if detailed else "low", "errors",
                    f"Felmeddelandet avslöjar teknik: {label}",
                    _clip(text[max(0, m.start() - 60):m.start() + 140], 220),
                    "Ger exakt ramverk, version och filväg — det som behövs för att välja exploit.",
                    "Egen 404/500-sida utan detaljer; logga internt i stället.")


def methods_scan(base):
    """OPTIONS tells us what the server would accept on a path, without writing."""
    for path in ("",):
        url = base.rstrip("/") + "/" + path
        status, h, _ = fetch(url, method="OPTIONS", timeout=PROBE_TIMEOUT)
        time.sleep(0.15)
        if not h:
            continue
        allow = (H(h, "allow") or "").upper()
        write = [m for m in ("PUT", "DELETE", "PATCH") if m in allow]
        if write:
            add(f"methods-{path or 'root'}", "low", "methods",
                f"Skrivmetoder annonseras på {'/' if not path else 'okänd sökväg'}",
                f"Allow: {allow} (annonserat, inte prövat — verktyget skriver aldrig)",
                "Är metoderna faktiskt aktiva och oskyddade kan innehåll ändras.",
                "Stäng av de metoder applikationen inte använder (405 på resten), "
                "och verifiera manuellt om de annonserade metoderna når data.")


def xdomain(base):
    for path, marker in (("crossdomain.xml", r'<allow-access-from[^>]*domain=["\']\*["\']'),
                         ("clientaccesspolicy.xml", r'<domain[^>]*uri=["\']\*["\']')):
        status, _, body = fetch(base.rstrip("/") + "/" + path, timeout=PROBE_TIMEOUT)
        time.sleep(0.1)
        if status == 200 and re.search(marker, _text(body), re.I):
            add(f"xdomain-{path}", "medium", "content",
                f"{path} tillåter alla domäner",
                _clip(_text(body), 160),
                "Ger alla sajter åtkomst till innehållet via plugin/Flash-bryggor som fortfarande läses av äldre klienter.",
                "Ta bort filen, eller begränsa till de domäner som faktiskt behöver den.")


def cached_auth_response(page):
    """An authenticated page that may be cached is one shared proxy from a leak."""
    if not any(k.lower() in ("cookie", "authorization") for k in EXTRA_HEADERS):
        return
    _, _, anon = fetch(page["url"], auth=False)
    if anon is not None and _text(anon)[:2000] == page["text"][:2000]:
        return      # samma sida utan credentials = ingen inloggad vy som kan läcka
    cc = (H(page["headers"], "cache-control") or "").lower()
    if "no-store" not in cc and "private" not in cc:
        add("auth-cacheable", "medium", "cookies",
            "Autentiserat svar saknar Cache-Control: no-store",
            f"cache-control: {cc or '(saknas)'}",
            "Delade cachar och historiken kan lämna ut inloggat innehåll till nästa användare.",
            "Cache-Control: no-store på allt som kräver inloggning.")


ACTIVE_AUTH = False
ACTIVE_AUTH_USER = None


def active_auth(base, page):
    """Two requests, one fake user: does the login form say who exists?
    Gated behind --active-auth — a wrong guess can trigger a lockout on production."""
    if not ACTIVE_AUTH:
        return
    if not ACTIVE_AUTH_USER:
        add("auth-user-missing", "info", "auth",
            "Kontoenumerering är inte prövad",
            "kräver --active-auth-user <ett testkonto du äger>",
            "Proben skickar två felaktiga inloggningar och kan låsa kontot — därför pekar du "
            "uttryckligen ut ett konto som får användas.",
            "Kör med --active-auth --active-auth-user <testkonto>.")
        return
    m = re.search(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', page["text"], re.S | re.I)
    if not m or 'type="password"' not in m.group(2).lower() and "type='password'" not in m.group(2).lower():
        add("no-login-form", "info", "auth", "Inget inloggningsformulär hittades på startsidan",
            fix="Kör med --url mot inloggningssidan om formuläret ligger någon annanstans.")
        return
    action = urllib.parse.urljoin(page["url"], m.group(1) or page["url"])
    try:
        same = _origin(action) == TARGET_ORIGIN
    except ValueError:
        same = False
    if not same:
        add("auth-foreign-action", "medium", "auth",
            "Inloggningsformuläret postar till ett annat origin",
            f"action: {action}",
            "Ett lösenord som skickas till en annan värd lämnar systemet — och en angripare kan "
            "också styra vart det tar vägen.",
            "Posta till egen origin; kontrollera action-attributet i mallen.")
        return
    user_field = "username"
    fm = re.search(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:type=["\'](?:text|email)["\'])', m.group(2), re.I)
    if fm:
        user_field = fm.group(1)
    results = {}
    for label, user in (("okänt konto", f"pretest-nonexistent-{random.randint(100000,999999)}"),
                        ("testkontot", ACTIVE_AUTH_USER)):
        data = urllib.parse.urlencode({user_field: user, "password": "Pretest!Wrong1"}).encode()
        status, h, body = fetch(action, method="POST", data=data,
                                headers={"Content-Type": "application/x-www-form-urlencoded"})
        results[label] = (status, len(body or b""), _text(body)[:400])
        time.sleep(0.4)
    a, b = results["okänd"], results["vanlig"]
    if a[0] != b[0] or abs(a[1] - b[1]) > 40 or (a[2][:120] != b[2][:120]):
        add("user-enumeration", "medium", "auth",
            "Inloggningen svarar olika för okänt konto och känt konto",
            f"okänt konto: {a[0]}/{a[1]}B · testkontot: {b[0]}/{b[1]}B",
            "Angriparen får en lista över vilka konton som finns innan lösenordsgissningen börjar.",
            "Samma svar, samma tid och samma text för alla fel — oavsett om kontot finns.")


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
    _, pem, err = _openssl(args, 25)
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
        return None      # None = kunde inte fråga; [] = frågade, fick inget svar
    try:
        return json.loads(body).get("Answer", [])
    except Exception:
        return None


def dns_checks(domain, delay=0.05):
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain or ""):
        return
    a, aaaa = doh(domain, "A"), doh(domain, "AAAA")
    if a is None or aaaa is None:
        add("dns-unavailable", "info", "dns", "DNS-kontrollerna kunde inte köras",
            "DoH svarade inte (timeout eller blockerad anslutning)",
            "E-post- och subdomänkontrollerna är oprövade — inte rena.",
            "Kör om, eller använd --no-dns för att slippa externa uppslag.")
        return
    if not (a + aaaa):
        add("dns-no-a", "info", "dns", "Domänen svarar inte på A/AAAA via DoH", domain)
    txt_raw = doh(domain, "TXT")
    if txt_raw is None:
        add("dns-unavailable-txt", "info", "email", "TXT-uppslaget misslyckades",
            "SPF/DMARC/DKIM är oprövade — inte frånvarande.")
        return
    txts = [x["data"].strip('"') for x in txt_raw]
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

    dm_raw = doh(f"_dmarc.{domain}", "TXT")
    dmarc = [t for t in (x["data"].strip('"') for x in (dm_raw or []))
             if t.lower().startswith("v=dmarc1")]
    if dm_raw is None:
        add("dns-unavailable-dmarc", "info", "email", "DMARC-uppslaget misslyckades — oprövat")
    elif not dmarc:
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

    caa = doh(domain, "CAA")
    if caa is None:
        add("dns-unavailable-caa", "info", "dns", "CAA-uppslaget misslyckades — oprövat")
    elif caa == []:
        add("no-caa", "low", "dns", "Ingen CAA-post",
            fix='CAA 0 issue "letsencrypt.org" — hindrar felaktig utfärdare.')

    subs = _crtsh(domain)
    if subs is None:
        add("dns-unavailable-crtsh", "info", "dns",
            "Kunde inte hämta subdomäner från crt.sh — oprövat")
        return []
    if subs:
        hits, takeovers, unverified = [], [], 0
        for name in subs[:120]:
            raw = doh(name, "CNAME")
            if raw is None:
                unverified += 1
                continue
            cnames = [x["data"].rstrip(".") for x in raw]
            if any(re.search(p, c.lower()) for c in cnames for p in TAKEOVER):
                takeovers.append(f"{name} -> {cnames[0]}")
            a_rec = doh(name, "A")
            if a_rec is None:
                unverified += 1
                continue
            if INTERESTING.search(name.split(".")[0]) and (cnames or a_rec):
                hits.append(name)
            time.sleep(delay)
        if takeovers:
            add("takeover-risk", "high", "dns", "Möjlig subdomain takeover",
                " · ".join(takeovers[:8]),
                "Pekare mot molntjänst som kan vara oregistrerad — angriparen tar över namnet.",
                "Verifiera varje pekare manuellt och ta bort de som inte används.")
        if unverified:
            add("dns-unavailable-subs", "info", "dns",
                f"{unverified} subdomäner kunde inte verifieras",
                "CNAME-uppslaget svarade inte — takeover-kontrollen är ofullständig där.")
        if hits:
            add("exposed-subdomains", "medium", "dns",
                f"{len(hits)} icke-produktionssubdomäner svarar", ", ".join(hits[:12]),
                "Utvecklingsyta är oftast svagare skyddad än produktion och sällan med i ett pentest-scope.",
                "Stäng av eller auth-skydda; lägg dem i scopet när du beställer test.")
    return subs


def _crtsh(domain):
    status, _, body = fetch(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30)
    if status != 200:
        return None
    try:
        rows = json.loads(body)
    except Exception:
        return None
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
    hits, seen, files = [], set(), 0
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
    try:
        global TARGET_ORIGIN
        TARGET_ORIGIN = _origin(base)   # credentials never leave the target origin
    except ValueError:
        add("bad-url", "info", "transport", "Ogiltig URL (port utanför 0-65535)", base)
        return
    page = http_checks(base, delay)
    if dest.scheme == "https":
        tls_checks(host, TARGET_ORIGIN[2])
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
Bifoga rapporten i scopet som underlag: den visar vad som redan är kontrollerat och
vad som uttryckligen är oprövat. Den ersätter inte ett penetrationstest och minskar
inte dess omfattning av sig själv — punkterna ovan ska fortfarande beställas."""


def report(target, as_json=False):
    target = _redact(target)
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

def _fixture_jwt():
    """Built at runtime: a literal that looks like a token gets redacted by editors and hooks."""
    enc = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    return enc({"alg": "none"}) + "." + enc({"sub": "1234567890"}) + "."


def _fixture_hs256(secret, kid=None):
    head = {"alg": "HS256", "typ": "JWT"}
    if kid:
        head["kid"] = kid
    enc = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    unsigned = f"{enc(head)}.{enc({'sub': '1', 'exp': 9999999999})}"
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), unsigned.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{unsigned}.{sig}"


def self_test():
    import http.server
    import threading

    global TARGET_ORIGIN, EXTRA_HEADERS

    jwt = _fixture_jwt()
    jwt_weak = _fixture_hs256("secret")
    jwt_kid = _fixture_hs256("a-real-long-secret-value-123", kid="../../../../etc/passwd")
    fake_aws = "AKIA" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16))

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            p = self.path.rstrip("/") or "/"
            if p in ("/", "/index.html"):
                body = (b"<html><body><!-- internal: db01.corp.local -->"
                        b"<script src=\"/app.js\"></script>"
                        b"<form action=\"/login\" method=\"post\"><input type=\"text\" name=\"user\">"
                        b"<input type=\"password\" name=\"password\"></form>"
                        b"<input type=\"hidden\" name=\"is_admin\" value=\"0\">"
                        b"<a href=\"/x\" target=\"_blank\">x</a>hej</body></html>")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Server", "TestSrv/0.9")
                self.send_header("Set-Cookie", "sid=abc123; Path=/")
                self.send_header("Set-Cookie", f"tok={jwt}; Path=/; HttpOnly; SameSite=Lax")
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
            elif p == "/app.js":
                body = (f'var k = "{fake_aws}";  // TODO rotate this before launch\n'
                        'fetch("http://10.0.0.5/internal/api");\n'
                        f'var t1 = "{jwt_weak}";\nvar t2 = "{jwt_kid}";\n').encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
            elif p == "/crossdomain.xml":
                body = b'<crossdomain-policy><allow-access-from domain="*"/></crossdomain-policy>'
                self.send_response(200)
                self.send_header("Content-Type", "text/x-cross-domain-policy")
            elif "pretest-err" in p:
                body = b"<html><h1>500</h1><pre>Traceback (most recent call last):</pre></html>"
                self.send_response(500)
                self.send_header("Content-Type", "text/html")
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
            self.send_header("Allow", "GET, OPTIONS, TRACE, PUT")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    GOOD_HEADERS = (
        ("Content-Type", "text/html"),
        ("Strict-Transport-Security", "max-age=63072000; includeSubDomains"),
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ("Permissions-Policy", "camera=(), microphone=()"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Cross-Origin-Resource-Policy", "same-origin"),
        ("X-Permitted-Cross-Domain-Policies", "none"),
        ("Cache-Control", "no-store"),
    )

    class GoodHandler(http.server.BaseHTTPRequestHandler):
        """En korrekt konfigurerad värd: får inte ge ett enda allvarligt fynd."""

        def do_GET(self):
            ok = self.path.rstrip("/") in ("", "/index.html")
            self.send_response(200 if ok else 404)
            for k, v in GOOD_HEADERS:
                self.send_header(k, v)
            if ok:
                self.send_header("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Lax")
            body = b"<html><body>ok</body></html>" if ok else b"nej"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header("Allow", "GET, HEAD, OPTIONS")
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

    expect = {"https-standard-port-unchecked", "exposed-.env", "exposed-.git-config",
              "cors-reflect-credentials", "cookie-flags-sid", "sourcemaps-public",
              "no-nosniff", "no-frame-protection", "trace-enabled",
              "js-secrets", "js-todo", "js-internal-hosts", "xdomain-crossdomain.xml",
              "html-comments", "hidden-fields", "noopener-missing", "jwt-alg-none",
              "jwt-no-exp", "jwt-weak-secret", "jwt-kid-injection",
              "methods-root", "error-leak-python-traceback"}
    problems = []
    got = set(FINDINGS)
    missing = expect - got
    if missing:
        problems.append("saknas: " + ", ".join(sorted(missing)))

    # an unexpected serious finding on the intentionally-bad fixture means over-reporting
    over = {i for i in got - expect if SEV_ORDER[FINDINGS[i]["sev"]] <= SEV_ORDER["medium"]}
    if over:
        problems.append("oväntade medium eller värre: " + ", ".join(sorted(over)))

    # severities are part of the contract, not decoration
    for fid, want in (("js-secrets", "critical"), ("jwt-alg-none", "medium"),
                      ("jwt-weak-secret", "high"), ("xdomain-crossdomain.xml", "medium"),
                      ("no-nosniff", "low")):
        if fid in FINDINGS and FINDINGS[fid]["sev"] != want:
            problems.append(f"{fid}: {FINDINGS[fid]['sev']} != {want}")

    # no secret may survive into the report or the JSON
    blob = json.dumps(FINDINGS, ensure_ascii=False)
    for secret in (fake_aws, jwt):
        if secret in blob:
            problems.append(f"hemlighet läckte till rapporten ({len(secret)} tecken)")

    # _redact is the only thing standing between a live secret and the report — test it directly
    sentinel = "pretestsentinelvalue123456"
    scrubbed = _redact(f"DB_PASSWORD=hunter2 token={sentinel} https://u:p@host/x sid={sentinel}")
    for leaked in ("hunter2", sentinel, "u:p@"):
        if leaked in scrubbed:
            problems.append(f"_redact lämnade kvar {leaked!r}")

    # regression: a 302 must never be followed, so credentials cannot travel with it
    saved = (TARGET_ORIGIN, dict(EXTRA_HEADERS))
    catcher = []

    class Bouncer(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{sinkport[0]}/loot")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    class Catcher(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            catcher.append(self.headers.get("Cookie"))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    sinkport = [0]
    cat = Quiet(("127.0.0.1", 0), Catcher)
    sinkport[0] = cat.server_address[1]
    threading.Thread(target=cat.serve_forever, daemon=True).start()
    bnc = Quiet(("127.0.0.1", 0), Bouncer)
    threading.Thread(target=bnc.serve_forever, daemon=True).start()
    try:
        TARGET_ORIGIN = ("http", "127.0.0.1", bnc.server_address[1])
        EXTRA_HEADERS.clear()
        EXTRA_HEADERS["Cookie"] = "session=pretest-fixture-cookie-1234567890"
        status, _, _ = fetch(f"http://127.0.0.1:{bnc.server_address[1]}/")
        if status != 302:
            problems.append(f"redirect följdes (status {status}, förväntade 302)")
        if catcher:
            problems.append("en 302 följdes och skickade credentials till annat origin")
    finally:
        TARGET_ORIGIN, EXTRA_HEADERS = saved
        cat.shutdown()
        bnc.shutdown()

    # regression: credentials must never follow a link to another origin (annat port eller värd)
    got_cookie = []

    class Sink(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            got_cookie.append(self.headers.get("Cookie"))
            body = b"var x=1;"
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    sink = Quiet(("127.0.0.1", 0), Sink)
    threading.Thread(target=sink.serve_forever, daemon=True).start()
    saved = (TARGET_ORIGIN, dict(EXTRA_HEADERS))
    try:
        TARGET_ORIGIN = ("http", "127.0.0.1", 9)      # ett annat origin än sinkens port
        EXTRA_HEADERS.clear()
        EXTRA_HEADERS["Cookie"] = "session=pretest-fixture-cookie-1234567890"
        probe_page = {"url": "http://127.0.0.1:9/", "headers": None,
                      "text": f'<html><script src="http://127.0.0.1:{sink.server_address[1]}/a.js">'
                              f'</script></html>'}
        js_analysis("http://127.0.0.1:9", probe_page)
    finally:
        TARGET_ORIGIN, EXTRA_HEADERS = saved
        sink.shutdown()
    if not got_cookie:
        problems.append("credential-regressionen mätte inget (sinken nåddes inte)")
    elif any(got_cookie):
        problems.append("KREDENTIALER LÄCKTE TILL ETT ANNAT ORIGIN")

    # a correctly configured host must produce nothing above low outside the http scheme itself
    FINDINGS.clear()
    good = Quiet(("127.0.0.1", 0), GoodHandler)
    threading.Thread(target=good.serve_forever, daemon=True).start()
    try:
        scan(f"http://127.0.0.1:{good.server_address[1]}", portscan=False, dns=False, delay=0)
    finally:
        good.shutdown()
    noisy = {i: f for i, f in FINDINGS.items()
             if f["area"] != "transport" and SEV_ORDER[f["sev"]] <= SEV_ORDER["medium"]}
    if noisy:
        problems.append("falska larm på en korrekt konfigurerad värd: "
                        + ", ".join(f"{i}({f['sev']})" for i, f in noisy.items()))

    # the reviewers' own counter-proof: a secret in any field must not survive add()
    FINDINGS.clear()
    opaque = "pretest-opaque-secret-987654321"
    add("redact-probe", "info", "x", "titel", evidence=opaque, why=opaque, fix=opaque)
    leaked_fields = [k for k, v in FINDINGS["redact-probe"].items() if opaque in str(v)]
    if leaked_fields:
        problems.append("_redact lämnade en hemlighet i fälten: " + ", ".join(leaked_fields))
    add("bad-url?secret=" + opaque, "info", opaque, "t")
    if opaque in json.dumps(FINDINGS, ensure_ascii=False, default=str):
        problems.append("_redact lämnade en hemlighet i id/area")
    if opaque in json.dumps(json.loads(report(f"https://u:{opaque}@127.0.0.1/", as_json=True)),
                            ensure_ascii=False):
        problems.append("_redact lämnade URL-userinfo i target")

    # the TLS path is otherwise untested: a self-signed host must be reported as such
    import ssl as _ssl
    import tempfile
    tls_dir = tempfile.mkdtemp()
    cert, key = os.path.join(tls_dir, "c.pem"), os.path.join(tls_dir, "k.pem")
    try:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=127.0.0.1", "-keyout", key, "-out", cert],
                       capture_output=True, timeout=60)
        tls_srv = Quiet(("127.0.0.1", 0), Handler)
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        tls_srv.socket = ctx.wrap_socket(tls_srv.socket, server_side=True)
        threading.Thread(target=tls_srv.serve_forever, daemon=True).start()
        FINDINGS.clear()
        tls_port = tls_srv.server_address[1]
        scan(f"https://127.0.0.1:{tls_port}", portscan=False, dns=False, delay=0)
        got_tls = FINDINGS.get("cert-untrusted")
        if not got_tls or got_tls["sev"] != "high":
            problems.append("TLS-kontrollen fångade inte ett självsignerat certifikat")
        if "tls-ok" not in FINDINGS and "tls-handshake" not in FINDINGS:
            problems.append("TLS-kontrollen kördes inte alls (ingen tls-post)")
        FINDINGS.clear()          # the standard-port branch, exercised against the same cert
        https_entry("127.0.0.1", 200, "http://127.0.0.1/", {}, port=tls_port)
        if FINDINGS.get("https-cert-broken", {}).get("sev") != "high":
            problems.append("https_entry skyllde inte ett trasigt certifikat på certifikatet")
        tls_srv.shutdown()
    except Exception as exc:
        problems.append(f"TLS-fixturen kunde inte köras: {exc!r}")

    print(f"self-test: {len(expect)} förväntade fynd, "
          f"{len(noisy)} falska larm på ren fixture, TLS-kontroll prövad")
    if problems:
        for pr in problems:
            print("FEL:", pr)
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
    ap.add_argument("--active-auth", action="store_true",
                    help="Pröva inloggningsformuläret för kontoenumerering (2 POST:ar)")
    ap.add_argument("--active-auth-user", metavar="NAMN",
                    help="Testkontot som proben får använda (krävs med --active-auth)")
    ap.add_argument("--fail-on", choices=list(SEV_ORDER), help="Exit 1 om fynd på denna nivå eller allvarligare")
    ap.add_argument("--self-test", action="store_true", help="Kör inbyggt test mot lokal fixtureserver")
    ap.add_argument("--version", action="version", version=f"pretest {VERSION}")
    args = ap.parse_args(argv)

    for raw in args.header:
        name, _, value = raw.partition(":")
        if not name.strip() or not value.strip():
            ap.error(f"--header måste vara 'Namn: värde', fick {raw!r}")
        EXTRA_HEADERS[name.strip()] = value.strip()

    global ACTIVE_AUTH, ACTIVE_AUTH_USER
    ACTIVE_AUTH = args.active_auth
    ACTIVE_AUTH_USER = args.active_auth_user

    if args.self_test:
        return self_test()
    if not args.url:
        ap.error("--url krävs (eller --self-test)")

    base = args.url if "://" in args.url else "https://" + args.url
    print(f"# pretest {VERSION} mot {_redact(base)} — endast mot system du äger eller har tillstånd att testa",
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
