"""
rift-manager.pro - Security Scanner SaaS
Backend FastAPI : authentification, scans de sécurité avec historique en base.
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import httpx
import ssl
import socket
import dns.resolver
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
import secrets

from database import Base, engine, get_db
import models
import schemas
import auth
import email_utils

app = FastAPI(title="Rift Manager Security Scanner", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://rift-manager.pro", "https://www.rift-manager.pro"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)


# ---------- Schémas du scan (inchangés) ----------

from pydantic import BaseModel


class ScanRequest(BaseModel):
    url: str


class ScanResult(BaseModel):
    target: str
    score: int
    grade: str
    vulnerabilities: list
    checks: dict
    scanned_at: str


# ---------- Utilitaires de scan ----------

SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEVERITY_LABEL_FR = {"critical": "Critique", "high": "Élevée", "medium": "Moyenne", "low": "Faible"}


def normalize_url(raw: str) -> str:
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


def grade_from_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def make_vuln(check_id: str, title: str, severity: str, risk: str, recommendation: str, evidence: str = "") -> dict:
    return {
        "check_id": check_id,
        "title": title,
        "severity": severity,
        "severity_label": SEVERITY_LABEL_FR.get(severity, severity),
        "risk": risk,
        "recommendation": recommendation,
        "evidence": evidence,
    }


SECURITY_HEADERS = {
    "strict-transport-security": {
        "weight": 15, "title": "En-tête HSTS manquant", "severity": "high",
        "risk": ("Sans Strict-Transport-Security, un navigateur peut être redirigé vers une version "
                  "non chiffrée (HTTP) du site, ce qui ouvre la porte à des attaques de type "
                  "« downgrade » ou interception sur un réseau non fiable (ex: Wi-Fi public)."),
        "recommendation": ("Ajoute l'en-tête : Strict-Transport-Security: max-age=31536000; includeSubDomains. "
                            "Cela force tous les navigateurs à toujours utiliser HTTPS pendant 1 an."),
    },
    "content-security-policy": {
        "weight": 15, "title": "En-tête CSP manquant", "severity": "high",
        "risk": ("Sans Content-Security-Policy, le site est plus vulnérable aux attaques XSS "
                  "(injection de scripts malveillants) car le navigateur exécutera n'importe quel "
                  "script injecté, qu'il vienne du site ou d'un attaquant."),
        "recommendation": ("Définis une politique stricte, par exemple : Content-Security-Policy: default-src 'self'. "
                            "Affine ensuite selon les ressources externes réellement utilisées."),
    },
    "x-content-type-options": {
        "weight": 10, "title": "En-tête X-Content-Type-Options manquant", "severity": "medium",
        "risk": ("Sans cet en-tête, certains navigateurs tentent de deviner le type d'un fichier "
                  "(« MIME sniffing »), ce qui peut permettre de faire exécuter un fichier malveillant "
                  "déguisé en image ou en document inoffensif."),
        "recommendation": "Ajoute l'en-tête : X-Content-Type-Options: nosniff sur toutes les réponses.",
    },
    "x-frame-options": {
        "weight": 10, "title": "En-tête X-Frame-Options manquant", "severity": "medium",
        "risk": ("Sans cette protection, le site peut être intégré dans une <iframe> sur un site "
                  "tiers malveillant, ouvrant la porte à des attaques de type clickjacking."),
        "recommendation": ("Ajoute l'en-tête : X-Frame-Options: DENY (ou SAMEORIGIN), "
                            "ou utilise frame-ancestors dans ta politique CSP."),
    },
    "referrer-policy": {
        "weight": 5, "title": "En-tête Referrer-Policy manquant", "severity": "low",
        "risk": ("Sans cet en-tête, l'URL complète de tes pages (parfois avec des paramètres sensibles) "
                  "peut être transmise à des sites tiers via l'en-tête Referer."),
        "recommendation": "Ajoute l'en-tête : Referrer-Policy: strict-origin-when-cross-origin.",
    },
    "permissions-policy": {
        "weight": 5, "title": "En-tête Permissions-Policy manquant", "severity": "low",
        "risk": ("Sans cet en-tête, des scripts tiers embarqués peuvent potentiellement accéder à la "
                  "caméra, au micro ou à la géolocalisation sans restriction explicite."),
        "recommendation": ("Ajoute l'en-tête : Permissions-Policy: camera=(), microphone=(), "
                            "geolocation=() pour désactiver ces accès si tu n'en as pas besoin."),
    },
}

SENSITIVE_PATHS = {
    "/.env": "Fichier de configuration contenant potentiellement des mots de passe, clés API ou secrets de base de données.",
    "/.git/config": "Configuration Git exposée, pouvant permettre de reconstruire tout l'historique du code source.",
    "/wp-config.php.bak": "Sauvegarde de configuration WordPress, contient généralement les identifiants de base de données.",
    "/backup.sql": "Export de base de données, peut contenir l'ensemble des données utilisateurs.",
    "/.DS_Store": "Fichier système macOS qui peut révéler la structure interne des dossiers du serveur.",
    "/config.json": "Fichier de configuration potentiellement sensible (clés, identifiants).",
    "/.aws/credentials": "Identifiants AWS qui donneraient un accès direct à l'infrastructure cloud.",
}

DANGEROUS_METHODS = ["TRACE", "PUT", "DELETE"]


# ---------- Checks individuels ----------

async def check_https_redirect(domain: str):
    http_url = f"http://{domain}"
    vulns = []
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=8) as client:
            resp = await client.get(http_url)
            redirects_to_https = (
                resp.status_code in (301, 302, 307, 308)
                and resp.headers.get("location", "").startswith("https://")
            )
            result = {
                "passed": redirects_to_https,
                "detail": "Redirection HTTP→HTTPS active" if redirects_to_https else "Pas de redirection forcée vers HTTPS détectée",
            }
            if not redirects_to_https:
                vulns.append(make_vuln(
                    check_id="https_redirect", title="Absence de redirection forcée vers HTTPS", severity="high",
                    risk=("Un visiteur tapant l'URL sans https:// reste en clair sur le réseau. Toutes les "
                          "données échangées peuvent être interceptées sur un réseau non fiable."),
                    recommendation="Configure ton serveur pour rediriger toute requête HTTP vers HTTPS avec un code 301/308.",
                    evidence=f"Statut {resp.status_code} reçu sur http://{domain}, sans redirection vers https://",
                ))
            return result, vulns
    except Exception as exc:
        result = {"passed": False, "detail": f"Impossible de joindre le site en HTTP ({exc})"}
        vulns.append(make_vuln(
            check_id="https_redirect", title="Impossible de vérifier la redirection HTTPS", severity="medium",
            risk="Le serveur n'a pas répondu sur le port 80.",
            recommendation="Vérifie manuellement que ton serveur écoute bien sur le port 80 et redirige vers HTTPS.",
            evidence=str(exc),
        ))
        return result, vulns


async def check_security_headers(url: str):
    found = {}
    points = 0
    vulns = []
    max_points = sum(h["weight"] for h in SECURITY_HEADERS.values())
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=8) as client:
            resp = await client.get(url)
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            for header, meta in SECURITY_HEADERS.items():
                present = header in headers_lower
                found[header] = present
                if present:
                    points += meta["weight"]
                else:
                    vulns.append(make_vuln(
                        check_id=f"header_{header}", title=meta["title"], severity=meta["severity"],
                        risk=meta["risk"], recommendation=meta["recommendation"],
                        evidence=f"En-tête '{header}' absent de la réponse HTTP",
                    ))
        return {"points": points, "max_points": max_points, "detail": found}, vulns
    except Exception as exc:
        return {"points": 0, "max_points": max_points, "detail": f"Erreur lors de la requête ({exc})"}, vulns


async def check_ssl_certificate(domain: str):
    vulns = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (not_after - datetime.now(timezone.utc)).days
                valid = days_left > 0
                result = {
                    "passed": valid, "days_left": days_left, "expires": cert["notAfter"],
                    "detail": f"Certificat valide, expire dans {days_left} jours" if valid else "Certificat expiré",
                }
                if not valid:
                    vulns.append(make_vuln(
                        check_id="ssl_expired", title="Certificat SSL expiré", severity="critical",
                        risk="Les navigateurs affichent un avertissement bloquant aux visiteurs.",
                        recommendation="Renouvelle immédiatement le certificat SSL.",
                        evidence=f"Le certificat a expiré le {cert['notAfter']}",
                    ))
                elif days_left < 14:
                    vulns.append(make_vuln(
                        check_id="ssl_expiring_soon", title="Certificat SSL bientôt expiré", severity="medium",
                        risk="Le certificat expire dans moins de 2 semaines.",
                        recommendation="Vérifie que le renouvellement automatique est bien configuré.",
                        evidence=f"Expire dans {days_left} jours ({cert['notAfter']})",
                    ))
                return result, vulns
    except Exception as exc:
        result = {"passed": False, "detail": f"Impossible de vérifier le certificat ({exc})"}
        vulns.append(make_vuln(
            check_id="ssl_unreachable", title="Certificat SSL non vérifiable", severity="high",
            risk="Impossible d'établir une connexion HTTPS valide.",
            recommendation="Vérifie que le port 443 est ouvert et qu'un certificat valide est installé.",
            evidence=str(exc),
        ))
        return result, vulns


async def check_exposed_files(url: str):
    exposed = []
    vulns = []
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=6) as client:
            probe_path = "/this-path-should-not-exist-rift-manager-probe-87263"
            baseline_content = None
            try:
                probe_resp = await client.get(url.rstrip("/") + probe_path)
                if probe_resp.status_code == 200:
                    baseline_content = probe_resp.content
            except Exception:
                pass

            for path, description in SENSITIVE_PATHS.items():
                try:
                    resp = await client.get(url.rstrip("/") + path)
                    content_type = resp.headers.get("content-type", "").lower()
                    looks_like_html = "text/html" in content_type
                    is_catch_all_response = resp.status_code == 200 and (
                        looks_like_html or (baseline_content is not None and resp.content == baseline_content)
                    )
                    if resp.status_code == 200 and len(resp.content) > 0 and not is_catch_all_response:
                        exposed.append(path)
                        vulns.append(make_vuln(
                            check_id=f"exposed_{path.strip('/').replace('/', '_')}",
                            title=f"Fichier sensible exposé : {path}", severity="critical",
                            risk=description,
                            recommendation=f"Restreins immédiatement l'accès public à {path}, ou supprime-le.",
                            evidence=f"Réponse HTTP 200 reçue sur {path}",
                        ))
                except Exception:
                    continue

            detail = "Aucun fichier sensible exposé détecté"
            if exposed:
                detail = f"{len(exposed)} fichier(s) potentiellement exposé(s)"
            elif baseline_content is not None:
                detail = "Aucun fichier sensible exposé (site à routage catch-all détecté, scan ajusté en conséquence)"

            return {"passed": len(exposed) == 0, "exposed_paths": exposed, "detail": detail}, vulns
    except Exception as exc:
        return {"passed": True, "exposed_paths": [], "detail": f"Scan incomplet ({exc})"}, vulns


async def check_spf_dmarc(domain: str):
    vulns = []
    spf_found = False
    dmarc_found = False
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        try:
            for rdata in resolver.resolve(domain, "TXT"):
                txt = b"".join(rdata.strings).decode(errors="ignore")
                if txt.startswith("v=spf1"):
                    spf_found = True
        except Exception:
            pass
        try:
            for rdata in resolver.resolve(f"_dmarc.{domain}", "TXT"):
                txt = b"".join(rdata.strings).decode(errors="ignore")
                if txt.startswith("v=DMARC1"):
                    dmarc_found = True
        except Exception:
            pass
    except Exception:
        pass

    if not spf_found:
        vulns.append(make_vuln(
            check_id="spf_missing", title="Enregistrement SPF manquant", severity="medium",
            risk="Sans SPF, n'importe qui peut envoyer des emails en usurpant le nom de domaine.",
            recommendation="Ajoute un enregistrement TXT SPF, ex : v=spf1 include:_spf.google.com ~all",
            evidence="Aucun enregistrement TXT commençant par 'v=spf1' trouvé",
        ))
    if not dmarc_found:
        vulns.append(make_vuln(
            check_id="dmarc_missing", title="Enregistrement DMARC manquant", severity="medium",
            risk="Sans DMARC, pas de politique claire contre les emails frauduleux usurpant le domaine.",
            recommendation="Ajoute un enregistrement TXT sur _dmarc.tondomaine.com, ex : v=DMARC1; p=quarantine;",
            evidence=f"Aucun enregistrement TXT trouvé sur _dmarc.{domain}",
        ))

    return {
        "spf_found": spf_found, "dmarc_found": dmarc_found, "passed": spf_found and dmarc_found,
        "detail": "SPF et DMARC configurés" if (spf_found and dmarc_found) else "Protection anti-usurpation d'email incomplète",
    }, vulns


async def check_cookies(url: str):
    vulns = []
    insecure_cookies = []
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=8) as client:
            resp = await client.get(url)
            raw = resp.headers.get("set-cookie")
            set_cookie_headers = [raw] if raw else []

            for cookie_str in set_cookie_headers:
                lower = cookie_str.lower()
                name = cookie_str.split("=")[0].strip()
                missing = []
                if "secure" not in lower:
                    missing.append("Secure")
                if "httponly" not in lower:
                    missing.append("HttpOnly")
                if "samesite" not in lower:
                    missing.append("SameSite")
                if missing:
                    insecure_cookies.append({"name": name, "missing": missing})

            for cookie in insecure_cookies:
                vulns.append(make_vuln(
                    check_id=f"cookie_{cookie['name']}", title=f"Cookie '{cookie['name']}' mal sécurisé", severity="medium",
                    risk=f"Attribut(s) manquant(s) : {', '.join(cookie['missing'])}. Risque de vol de session ou CSRF.",
                    recommendation="Ajoute les attributs manquants : Set-Cookie: ...; Secure; HttpOnly; SameSite=Strict",
                    evidence=f"Cookie observé sans : {', '.join(cookie['missing'])}",
                ))

            return {
                "passed": len(insecure_cookies) == 0, "cookies_checked": len(set_cookie_headers),
                "detail": "Aucun cookie détecté ou tous correctement sécurisés" if not insecure_cookies else f"{len(insecure_cookies)} cookie(s) avec attributs manquants",
            }, vulns
    except Exception as exc:
        return {"passed": True, "cookies_checked": 0, "detail": f"Scan incomplet ({exc})"}, vulns


async def check_cors(url: str):
    vulns = []
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=8) as client:
            resp = await client.get(url, headers={"Origin": "https://attacker-test-rift-manager.example"})
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")
            wildcard_with_credentials = acao == "*" and acac.lower() == "true"
            reflects_arbitrary_origin = acao == "https://attacker-test-rift-manager.example"

            if wildcard_with_credentials:
                vulns.append(make_vuln(
                    check_id="cors_wildcard_credentials", title="CORS : wildcard combiné aux credentials", severity="critical",
                    risk="N'importe quel site tiers peut faire des requêtes authentifiées au nom d'une victime connectée.",
                    recommendation="Ne jamais combiner Access-Control-Allow-Origin: * avec Allow-Credentials: true.",
                    evidence="Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true",
                ))
            elif reflects_arbitrary_origin:
                vulns.append(make_vuln(
                    check_id="cors_reflects_origin", title="CORS : réflexion arbitraire de l'origine", severity="high",
                    risk="Le serveur autorise n'importe quel site tiers à interagir avec cette API.",
                    recommendation="Valide l'origine contre une liste blanche explicite côté serveur.",
                    evidence=f"Origin de test renvoyée telle quelle : {acao}",
                ))

            passed = not (wildcard_with_credentials or reflects_arbitrary_origin)
            return {"passed": passed, "detail": "Configuration CORS correcte" if passed else "Configuration CORS trop permissive détectée"}, vulns
    except Exception as exc:
        return {"passed": True, "detail": f"Scan incomplet ({exc})"}, vulns


async def check_tls_version(domain: str):
    vulns = []
    obsolete_supported = []
    for version_name, ssl_version in [
        ("TLSv1.0", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1),
        ("TLSv1.1", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1_1),
    ]:
        if ssl_version is None:
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl_version
            ctx.maximum_version = ssl_version
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain):
                    obsolete_supported.append(version_name)
        except Exception:
            continue

    if obsolete_supported:
        vulns.append(make_vuln(
            check_id="tls_obsolete", title=f"Versions TLS obsolètes acceptées ({', '.join(obsolete_supported)})", severity="high",
            risk="TLS 1.0/1.1 présentent des faiblesses cryptographiques connues (BEAST, POODLE).",
            recommendation="Désactive TLS 1.0 et 1.1, n'autorise que TLS 1.2 et 1.3.",
            evidence=f"Le serveur a accepté une connexion en : {', '.join(obsolete_supported)}",
        ))

    return {
        "passed": len(obsolete_supported) == 0, "obsolete_versions": obsolete_supported,
        "detail": "Seules des versions TLS modernes sont acceptées" if not obsolete_supported else f"Versions obsolètes encore acceptées : {', '.join(obsolete_supported)}",
    }, vulns


async def check_server_info_disclosure(url: str):
    vulns = []
    disclosed = {}
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=8) as client:
            resp = await client.get(url)
            for header in ("server", "x-powered-by"):
                value = resp.headers.get(header)
                if value and any(char.isdigit() for char in value):
                    disclosed[header] = value

            for header, value in disclosed.items():
                vulns.append(make_vuln(
                    check_id=f"info_disclosure_{header}", title=f"Version exacte révélée via l'en-tête {header}", severity="low",
                    risk=f"L'en-tête '{header}' révèle '{value}', facilitant la recherche de CVE connues.",
                    recommendation=f"Masque ou généralise l'en-tête '{header}' (ex: server_tokens off; sur Nginx).",
                    evidence=f"{header}: {value}",
                ))

            return {
                "passed": len(disclosed) == 0, "disclosed_headers": disclosed,
                "detail": "Aucune version précise exposée" if not disclosed else "Informations de version exposées dans les en-têtes",
            }, vulns
    except Exception as exc:
        return {"passed": True, "disclosed_headers": {}, "detail": f"Scan incomplet ({exc})"}, vulns


async def check_dangerous_http_methods(url: str):
    vulns = []
    enabled = []
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=8) as client:
            for method in DANGEROUS_METHODS:
                try:
                    resp = await client.request(method, url)
                    if resp.status_code not in (405, 501, 403, 404):
                        enabled.append(method)
                except Exception:
                    continue

            for method in enabled:
                severity = "high" if method == "TRACE" else "medium"
                risk = (
                    "La méthode TRACE peut être utilisée dans des attaques XST pour contourner HttpOnly."
                    if method == "TRACE" else
                    f"La méthode {method} activée sans contrôle d'accès strict peut permettre de modifier des ressources."
                )
                vulns.append(make_vuln(
                    check_id=f"http_method_{method.lower()}", title=f"Méthode HTTP {method} activée", severity=severity,
                    risk=risk, recommendation=f"Désactive la méthode {method} au niveau du serveur web.",
                    evidence=f"Réponse différente de 403/404/405/501 reçue pour la méthode {method}",
                ))

            return {
                "passed": len(enabled) == 0, "enabled_methods": enabled,
                "detail": "Aucune méthode HTTP risquée activée" if not enabled else f"Méthode(s) activée(s) : {', '.join(enabled)}",
            }, vulns
    except Exception as exc:
        return {"passed": True, "enabled_methods": [], "detail": f"Scan incomplet ({exc})"}, vulns


async def run_full_scan(url: str) -> ScanResult:
    url = normalize_url(url)
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    if not domain:
        raise HTTPException(status_code=400, detail="URL invalide")

    https_redirect, v1 = await check_https_redirect(domain)
    headers_check, v2 = await check_security_headers(url)
    ssl_check, v3 = await check_ssl_certificate(domain)
    files_check, v4 = await check_exposed_files(url)
    spf_dmarc_check, v5 = await check_spf_dmarc(domain)
    cookies_check, v6 = await check_cookies(url)
    cors_check, v7 = await check_cors(url)
    tls_check, v8 = await check_tls_version(domain)
    server_info_check, v9 = await check_server_info_disclosure(url)
    methods_check, v10 = await check_dangerous_http_methods(url)

    all_vulns = v1 + v2 + v3 + v4 + v5 + v6 + v7 + v8 + v9 + v10
    all_vulns.sort(key=lambda v: SEVERITY_WEIGHT.get(v["severity"], 0), reverse=True)

    score = 0
    score += 12 if https_redirect["passed"] else 0
    score += round((headers_check["points"] / headers_check["max_points"]) * 25) if headers_check["max_points"] else 0
    score += 15 if ssl_check["passed"] else 0
    score += 10 if files_check["passed"] else 0
    score += 8 if spf_dmarc_check["passed"] else 0
    score += 8 if cookies_check["passed"] else 0
    score += 8 if cors_check["passed"] else 0
    score += 8 if tls_check["passed"] else 0
    score += 3 if server_info_check["passed"] else 0
    score += 3 if methods_check["passed"] else 0
    score = min(score, 100)

    return ScanResult(
        target=domain, score=score, grade=grade_from_score(score), vulnerabilities=all_vulns,
        checks={
            "https_redirect": https_redirect, "security_headers": headers_check, "ssl_certificate": ssl_check,
            "exposed_files": files_check, "spf_dmarc": spf_dmarc_check, "cookies": cookies_check,
            "cors": cors_check, "tls_version": tls_check, "server_info_disclosure": server_info_check,
            "dangerous_http_methods": methods_check,
        },
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )


# ---------- Endpoints d'authentification ----------

@app.post("/auth/register", response_model=schemas.TokenResponse)
def register(request: schemas.RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.email == request.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Un compte existe déjà avec cet email")

    if len(request.password) < 8:
        raise HTTPException(status_code=400, detail="Le mot de passe doit contenir au moins 8 caractères")

    user = models.User(email=request.email, hashed_password=auth.hash_password(request.password))
    db.add(user)
    db.commit()
    db.refresh(user)

    token = auth.create_access_token(user.id)
    return schemas.TokenResponse(access_token=token)


@app.post("/auth/login", response_model=schemas.TokenResponse)
def login(request: schemas.LoginRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if not user or not auth.verify_password(request.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")

    token = auth.create_access_token(user.id)
    return schemas.TokenResponse(access_token=token)


RESET_TOKEN_EXPIRE_MINUTES = 30


@app.post("/auth/forgot-password")
async def forgot_password(request: schemas.ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == request.email).first()

    # Toujours renvoyer le même message, qu'un compte existe ou non,
    # pour éviter de révéler quels emails sont inscrits (énumération de comptes).
    generic_response = {"status": "ok", "detail": "Si un compte existe avec cet email, un lien de réinitialisation a été envoyé."}

    if not user:
        return generic_response

    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES)

    reset_token = models.PasswordResetToken(user_id=user.id, token=token, expires_at=expires_at)
    db.add(reset_token)
    db.commit()

    reset_link = f"https://www.rift-manager.pro/reset-password.html?token={token}"
    html = (
        f"<p>Tu as demandé à réinitialiser ton mot de passe Rift Manager.</p>"
        f"<p><a href='{reset_link}'>Clique ici pour choisir un nouveau mot de passe</a></p>"
        f"<p>Ce lien expire dans {RESET_TOKEN_EXPIRE_MINUTES} minutes. Si tu n'es pas à l'origine "
        f"de cette demande, tu peux ignorer cet email.</p>"
    )
    await email_utils.send_email(user.email, "Réinitialisation de ton mot de passe Rift Manager", html)

    return generic_response


@app.post("/auth/reset-password")
def reset_password(request: schemas.ResetPasswordRequest, db: Session = Depends(get_db)):
    reset_token = (
        db.query(models.PasswordResetToken)
        .filter(models.PasswordResetToken.token == request.token)
        .first()
    )

    if not reset_token or reset_token.used:
        raise HTTPException(status_code=400, detail="Lien de réinitialisation invalide ou déjà utilisé")

    if reset_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Lien de réinitialisation expiré, refais une demande")

    if len(request.new_password) < 8:
        raise HTTPException(status_code=400, detail="Le mot de passe doit contenir au moins 8 caractères")

    user = db.query(models.User).filter(models.User.id == reset_token.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")

    user.hashed_password = auth.hash_password(request.new_password)
    reset_token.used = True
    db.commit()

    return {"status": "ok", "detail": "Mot de passe mis à jour, tu peux te connecter"}


@app.get("/auth/me", response_model=schemas.UserOut)
def get_me(current_user: models.User = Depends(auth.get_current_user)):
    return current_user


@app.put("/auth/me", response_model=schemas.UserOut)
def update_me(
    request: schemas.UpdateProfileRequest,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    if request.new_password:
        if not request.current_password or not auth.verify_password(request.current_password, current_user.hashed_password):
            raise HTTPException(status_code=400, detail="Mot de passe actuel incorrect")
        if len(request.new_password) < 8:
            raise HTTPException(status_code=400, detail="Le nouveau mot de passe doit contenir au moins 8 caractères")
        current_user.hashed_password = auth.hash_password(request.new_password)

    if request.email and request.email != current_user.email:
        existing = db.query(models.User).filter(models.User.email == request.email).first()
        if existing:
            raise HTTPException(status_code=400, detail="Cet email est déjà utilisé")
        current_user.email = request.email

    db.commit()
    db.refresh(current_user)
    return current_user


@app.delete("/auth/me")
def delete_me(current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    db.delete(current_user)
    db.commit()
    return {"status": "ok", "detail": "Compte supprimé"}


# ---------- Endpoint de scan (protégé) ----------

@app.post("/scan", response_model=ScanResult)
async def scan(
    request: ScanRequest,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    result = await run_full_scan(request.url)

    record = models.ScanRecord(
        user_id=current_user.id,
        target=result.target,
        score=result.score,
        grade=result.grade,
        result_json=result.model_dump(),
    )
    db.add(record)
    db.commit()

    return result


@app.get("/scans/history", response_model=list[schemas.ScanHistoryItem])
def scan_history(
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    records = (
        db.query(models.ScanRecord)
        .filter(models.ScanRecord.user_id == current_user.id)
        .order_by(models.ScanRecord.created_at.desc())
        .limit(50)
        .all()
    )
    return records


@app.get("/scans/history/{scan_id}")
def scan_detail(
    scan_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    record = (
        db.query(models.ScanRecord)
        .filter(models.ScanRecord.id == scan_id, models.ScanRecord.user_id == current_user.id)
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    return record.result_json


@app.get("/")
async def root():
    return {"status": "ok", "service": "Rift Manager Security Scanner"}


@app.get("/health")
async def health():
    return {"status": "healthy"}
