"""
rift-manager.pro - Security Scanner MVP
Backend FastAPI : scanne un domaine et retourne un score de sécurité /100
avec un détail précis de chaque vulnérabilité détectée.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

app = FastAPI(title="Rift Manager Security Scanner", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://rift-manager.pro", "https://www.rift-manager.pro"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str


class ScanResult(BaseModel):
    target: str
    score: int
    grade: str
    vulnerabilities: list
    checks: dict
    scanned_at: str


# ---------- Utilitaires ----------

SEVERITY_WEIGHT = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}

SEVERITY_LABEL_FR = {
    "critical": "Critique",
    "high": "Élevée",
    "medium": "Moyenne",
    "low": "Faible",
}


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
    """Construit un objet vulnérabilité standardisé."""
    return {
        "check_id": check_id,
        "title": title,
        "severity": severity,
        "severity_label": SEVERITY_LABEL_FR.get(severity, severity),
        "risk": risk,
        "recommendation": recommendation,
        "evidence": evidence,
    }


# ---------- Base de connaissances : headers de sécurité ----------

SECURITY_HEADERS = {
    "strict-transport-security": {
        "weight": 15,
        "title": "En-tête HSTS manquant",
        "severity": "high",
        "risk": (
            "Sans Strict-Transport-Security, un navigateur peut être redirigé vers une version "
            "non chiffrée (HTTP) du site, ce qui ouvre la porte à des attaques de type "
            "« downgrade » ou interception sur un réseau non fiable (ex: Wi-Fi public)."
        ),
        "recommendation": (
            "Ajoute l'en-tête : Strict-Transport-Security: max-age=31536000; includeSubDomains. "
            "Cela force tous les navigateurs à toujours utiliser HTTPS pendant 1 an, même si "
            "l'utilisateur tape l'URL en http://."
        ),
    },
    "content-security-policy": {
        "weight": 15,
        "title": "En-tête CSP manquant",
        "severity": "high",
        "risk": (
            "Sans Content-Security-Policy, le site est plus vulnérable aux attaques XSS "
            "(injection de scripts malveillants) car le navigateur exécutera n'importe quel "
            "script injecté, qu'il vienne du site ou d'un attaquant."
        ),
        "recommendation": (
            "Définis une politique stricte, par exemple : Content-Security-Policy: default-src 'self'. "
            "Affine ensuite selon les ressources externes réellement utilisées (CDN, polices, etc.)."
        ),
    },
    "x-content-type-options": {
        "weight": 10,
        "title": "En-tête X-Content-Type-Options manquant",
        "severity": "medium",
        "risk": (
            "Sans cet en-tête, certains navigateurs tentent de deviner le type d'un fichier "
            "(« MIME sniffing »), ce qui peut permettre de faire exécuter un fichier malveillant "
            "déguisé en image ou en document inoffensif."
        ),
        "recommendation": "Ajoute l'en-tête : X-Content-Type-Options: nosniff sur toutes les réponses.",
    },
    "x-frame-options": {
        "weight": 10,
        "title": "En-tête X-Frame-Options manquant",
        "severity": "medium",
        "risk": (
            "Sans cette protection, le site peut être intégré dans une <iframe> sur un site "
            "tiers malveillant, ouvrant la porte à des attaques de type clickjacking "
            "(l'utilisateur croit cliquer sur un élément alors qu'il interagit avec ton site caché)."
        ),
        "recommendation": (
            "Ajoute l'en-tête : X-Frame-Options: DENY (ou SAMEORIGIN si tu as besoin d'iframes internes), "
            "ou utilise frame-ancestors dans ta politique CSP."
        ),
    },
    "referrer-policy": {
        "weight": 5,
        "title": "En-tête Referrer-Policy manquant",
        "severity": "low",
        "risk": (
            "Sans cet en-tête, l'URL complète de tes pages (parfois avec des paramètres sensibles "
            "comme des tokens) peut être transmise à des sites tiers via l'en-tête Referer lors "
            "d'un clic sortant."
        ),
        "recommendation": "Ajoute l'en-tête : Referrer-Policy: strict-origin-when-cross-origin.",
    },
    "permissions-policy": {
        "weight": 5,
        "title": "En-tête Permissions-Policy manquant",
        "severity": "low",
        "risk": (
            "Sans cet en-tête, des scripts tiers embarqués (publicités, widgets) peuvent potentiellement "
            "accéder à la caméra, au micro ou à la géolocalisation sans restriction explicite."
        ),
        "recommendation": (
            "Ajoute l'en-tête : Permissions-Policy: camera=(), microphone=(), geolocation=() "
            "pour désactiver ces accès si tu n'en as pas besoin."
        ),
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


# ---------- Checks individuels ----------

async def check_https_redirect(domain: str):
    """Vérifie qu'une requête HTTP redirige bien vers HTTPS."""
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
                "detail": "Redirection HTTP→HTTPS active"
                if redirects_to_https
                else "Pas de redirection forcée vers HTTPS détectée",
            }
            if not redirects_to_https:
                vulns.append(make_vuln(
                    check_id="https_redirect",
                    title="Absence de redirection forcée vers HTTPS",
                    severity="high",
                    risk=(
                        "Un visiteur tapant l'URL sans https:// (ou cliquant un vieux lien en http://) "
                        "reste en clair sur le réseau. Toutes les données échangées (identifiants, "
                        "formulaires, cookies) peuvent être interceptées par un attaquant en position "
                        "d'interception réseau (Wi-Fi public, proxy malveillant, etc.)."
                    ),
                    recommendation=(
                        "Configure ton serveur web ou ton CDN pour rediriger systématiquement toute "
                        "requête HTTP (port 80) vers la version HTTPS avec un code 301 ou 308."
                    ),
                    evidence=f"Statut {resp.status_code} reçu sur http://{domain}, sans redirection vers https://",
                ))
            return result, vulns
    except Exception as exc:
        result = {"passed": False, "detail": f"Impossible de joindre le site en HTTP ({exc})"}
        vulns.append(make_vuln(
            check_id="https_redirect",
            title="Impossible de vérifier la redirection HTTPS",
            severity="medium",
            risk="Le serveur n'a pas répondu sur le port 80, ce qui empêche de confirmer le comportement de sécurité attendu.",
            recommendation="Vérifie manuellement que ton serveur écoute bien sur le port 80 et redirige vers HTTPS.",
            evidence=str(exc),
        ))
        return result, vulns


async def check_security_headers(url: str):
    """Vérifie la présence des headers de sécurité HTTP courants."""
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
                        check_id=f"header_{header}",
                        title=meta["title"],
                        severity=meta["severity"],
                        risk=meta["risk"],
                        recommendation=meta["recommendation"],
                        evidence=f"En-tête '{header}' absent de la réponse HTTP",
                    ))
        return {"points": points, "max_points": max_points, "detail": found}, vulns
    except Exception as exc:
        return {
            "points": 0,
            "max_points": max_points,
            "detail": f"Erreur lors de la requête ({exc})",
        }, vulns


async def check_ssl_certificate(domain: str):
    """Vérifie la validité et l'expiration du certificat SSL."""
    vulns = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                days_left = (not_after - datetime.now(timezone.utc)).days
                valid = days_left > 0
                result = {
                    "passed": valid,
                    "days_left": days_left,
                    "expires": cert["notAfter"],
                    "detail": f"Certificat valide, expire dans {days_left} jours"
                    if valid
                    else "Certificat expiré",
                }
                if not valid:
                    vulns.append(make_vuln(
                        check_id="ssl_expired",
                        title="Certificat SSL expiré",
                        severity="critical",
                        risk=(
                            "Les navigateurs affichent un avertissement de sécurité bloquant aux visiteurs, "
                            "et toutes les connexions HTTPS sont considérées comme non fiables. Cela coupe "
                            "l'accès au site pour la majorité des utilisateurs et nuit gravement à la confiance."
                        ),
                        recommendation="Renouvelle immédiatement le certificat SSL (Let's Encrypt en automatique si possible).",
                        evidence=f"Le certificat a expiré le {cert['notAfter']}",
                    ))
                elif days_left < 14:
                    vulns.append(make_vuln(
                        check_id="ssl_expiring_soon",
                        title="Certificat SSL bientôt expiré",
                        severity="medium",
                        risk=(
                            "Si le renouvellement n'est pas automatisé, le certificat va expirer dans "
                            "moins de 2 semaines, ce qui rendra le site inaccessible en HTTPS."
                        ),
                        recommendation="Vérifie que le renouvellement automatique est bien configuré, ou renouvelle manuellement dès que possible.",
                        evidence=f"Expire dans {days_left} jours ({cert['notAfter']})",
                    ))
                return result, vulns
    except Exception as exc:
        result = {"passed": False, "detail": f"Impossible de vérifier le certificat ({exc})"}
        vulns.append(make_vuln(
            check_id="ssl_unreachable",
            title="Certificat SSL non vérifiable",
            severity="high",
            risk=(
                "Impossible d'établir une connexion HTTPS valide. Le site peut être inaccessible en HTTPS, "
                "ou présenter un certificat invalide/auto-signé que les navigateurs rejettent."
            ),
            recommendation="Vérifie que le port 443 est ouvert et qu'un certificat valide est bien installé sur le serveur.",
            evidence=str(exc),
        ))
        return result, vulns


async def check_exposed_files(url: str):
    """Teste l'exposition de fichiers/chemins sensibles courants.

    Beaucoup de sites (SPA React/Vue, certains CMS) renvoient un statut 200
    avec leur page d'accueil pour N'IMPORTE QUELLE URL au lieu d'un vrai 404.
    On détecte ce comportement en testant d'abord une URL bidon : si elle
    renvoie aussi 200 avec un contenu identique, on sait que le site a un
    comportement "catch-all" et on ignore les faux positifs qui en découlent.
    """
    exposed = []
    vulns = []
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=6) as client:
            # Détection du comportement catch-all (faux positif systématique)
            probe_path = "/this-path-should-not-exist-rift-manager-probe-87263"
            baseline_content = None
            baseline_length = None
            try:
                probe_resp = await client.get(url.rstrip("/") + probe_path)
                if probe_resp.status_code == 200:
                    baseline_content = probe_resp.content
                    baseline_length = len(probe_resp.content)
            except Exception:
                pass

            for path, description in SENSITIVE_PATHS.items():
                try:
                    resp = await client.get(url.rstrip("/") + path)
                    content_type = resp.headers.get("content-type", "").lower()
                    looks_like_html = "text/html" in content_type

                    is_catch_all_response = resp.status_code == 200 and (
                        looks_like_html  # un vrai .env/.sql/.json n'est jamais servi en HTML
                        or (baseline_content is not None and resp.content == baseline_content)
                    )
                    if resp.status_code == 200 and len(resp.content) > 0 and not is_catch_all_response:
                        exposed.append(path)
                        vulns.append(make_vuln(
                            check_id=f"exposed_{path.strip('/').replace('/', '_')}",
                            title=f"Fichier sensible exposé : {path}",
                            severity="critical",
                            risk=description,
                            recommendation=(
                                f"Restreins immédiatement l'accès public à {path} via la configuration de ton "
                                "serveur web (règle de blocage Nginx/Apache), ou supprime-le du dossier public "
                                "s'il n'a pas besoin d'y être."
                            ),
                            evidence=f"Réponse HTTP 200 reçue sur {path}",
                        ))
                except Exception:
                    continue
        catch_all_detected = baseline_content is not None and len(exposed) == 0
        detail = "Aucun fichier sensible exposé détecté"
        if exposed:
            detail = f"{len(exposed)} fichier(s) potentiellement exposé(s)"
        elif catch_all_detected:
            detail = "Aucun fichier sensible exposé (site à routage catch-all détecté, scan ajusté en conséquence)"

        return {
            "passed": len(exposed) == 0,
            "exposed_paths": exposed,
            "detail": detail,
        }, vulns
    except Exception as exc:
        return {"passed": True, "exposed_paths": [], "detail": f"Scan incomplet ({exc})"}, vulns


# ---------- Endpoint principal ----------

@app.post("/scan", response_model=ScanResult)
async def scan(request: ScanRequest):
    url = normalize_url(request.url)
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path

    if not domain:
        raise HTTPException(status_code=400, detail="URL invalide")

    https_redirect, v1 = await check_https_redirect(domain)
    headers_check, v2 = await check_security_headers(url)
    ssl_check, v3 = await check_ssl_certificate(domain)
    files_check, v4 = await check_exposed_files(url)

    all_vulns = v1 + v2 + v3 + v4
    all_vulns.sort(key=lambda v: SEVERITY_WEIGHT.get(v["severity"], 0), reverse=True)

    score = 0
    score += 20 if https_redirect["passed"] else 0
    score += round((headers_check["points"] / headers_check["max_points"]) * 40) if headers_check["max_points"] else 0
    score += 25 if ssl_check["passed"] else 0
    score += 15 if files_check["passed"] else 0
    score = min(score, 100)

    return ScanResult(
        target=domain,
        score=score,
        grade=grade_from_score(score),
        vulnerabilities=all_vulns,
        checks={
            "https_redirect": https_redirect,
            "security_headers": headers_check,
            "ssl_certificate": ssl_check,
            "exposed_files": files_check,
        },
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )


@app.get("/")
async def root():
    return {"status": "ok", "service": "Rift Manager Security Scanner"}


@app.get("/health")
async def health():
    return {"status": "healthy"}
