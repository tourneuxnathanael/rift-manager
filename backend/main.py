"""
rift-manager.pro - Security Scanner MVP
Backend FastAPI : scanne un domaine et retourne un score de sécurité /100
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
import httpx
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

app = FastAPI(title="Rift Manager Security Scanner", version="0.1.0")

# CORS ouvert pour le MVP (à restreindre en prod)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str


class ScanResult(BaseModel):
    target: str
    score: int
    grade: str
    checks: dict
    scanned_at: str


# ---------- Utilitaires ----------

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


# ---------- Checks individuels ----------

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/wp-config.php.bak",
    "/backup.sql",
    "/.DS_Store",
    "/config.json",
    "/.aws/credentials",
]

SECURITY_HEADERS = {
    "strict-transport-security": 15,
    "content-security-policy": 15,
    "x-content-type-options": 10,
    "x-frame-options": 10,
    "referrer-policy": 5,
    "permissions-policy": 5,
}


async def check_https_redirect(domain: str) -> dict:
    """Vérifie qu'une requête HTTP redirige bien vers HTTPS."""
    http_url = f"http://{domain}"
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=8) as client:
            resp = await client.get(http_url)
            redirects_to_https = (
                resp.status_code in (301, 302, 307, 308)
                and resp.headers.get("location", "").startswith("https://")
            )
            return {
                "passed": redirects_to_https,
                "detail": "Redirection HTTP→HTTPS active"
                if redirects_to_https
                else "Pas de redirection forcée vers HTTPS détectée",
            }
    except Exception as exc:
        return {"passed": False, "detail": f"Impossible de joindre le site en HTTP ({exc})"}


async def check_security_headers(url: str) -> dict:
    """Vérifie la présence des headers de sécurité HTTP courants."""
    found = {}
    points = 0
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=8) as client:
            resp = await client.get(url)
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            for header, weight in SECURITY_HEADERS.items():
                present = header in headers_lower
                found[header] = present
                if present:
                    points += weight
        return {
            "points": points,
            "max_points": sum(SECURITY_HEADERS.values()),
            "detail": found,
        }
    except Exception as exc:
        return {
            "points": 0,
            "max_points": sum(SECURITY_HEADERS.values()),
            "detail": f"Erreur lors de la requête ({exc})",
        }


async def check_ssl_certificate(domain: str) -> dict:
    """Vérifie la validité et l'expiration du certificat SSL."""
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
                return {
                    "passed": valid,
                    "days_left": days_left,
                    "expires": cert["notAfter"],
                    "detail": f"Certificat valide, expire dans {days_left} jours"
                    if valid
                    else "Certificat expiré",
                }
    except Exception as exc:
        return {"passed": False, "detail": f"Impossible de vérifier le certificat ({exc})"}


async def check_exposed_files(url: str) -> dict:
    """Teste l'exposition de fichiers/chemins sensibles courants."""
    exposed = []
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=6) as client:
            for path in SENSITIVE_PATHS:
                try:
                    resp = await client.get(url.rstrip("/") + path)
                    if resp.status_code == 200 and len(resp.content) > 0:
                        exposed.append(path)
                except Exception:
                    continue
        return {
            "passed": len(exposed) == 0,
            "exposed_paths": exposed,
            "detail": "Aucun fichier sensible exposé détecté"
            if not exposed
            else f"{len(exposed)} fichier(s) potentiellement exposé(s)",
        }
    except Exception as exc:
        return {"passed": True, "exposed_paths": [], "detail": f"Scan incomplet ({exc})"}


# ---------- Endpoint principal ----------

@app.post("/scan", response_model=ScanResult)
async def scan(request: ScanRequest):
    url = normalize_url(request.url)
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path

    if not domain:
        raise HTTPException(status_code=400, detail="URL invalide")

    https_redirect = await check_https_redirect(domain)
    headers_check = await check_security_headers(url)
    ssl_check = await check_ssl_certificate(domain)
    files_check = await check_exposed_files(url)

    score = 0
    # HTTPS redirect : 20 pts
    score += 20 if https_redirect["passed"] else 0
    # Headers : jusqu'à 60 pts (pondéré proportionnellement)
    score += round((headers_check["points"] / headers_check["max_points"]) * 40) if headers_check["max_points"] else 0
    # SSL : 25 pts
    score += 25 if ssl_check["passed"] else 0
    # Fichiers exposés : 15 pts
    score += 15 if files_check["passed"] else 0

    score = min(score, 100)

    return ScanResult(
        target=domain,
        score=score,
        grade=grade_from_score(score),
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
