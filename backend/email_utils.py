"""Envoi d'emails via l'API Resend. Si RESEND_API_KEY n'est pas configurée,
le contenu de l'email est simplement affiché dans les logs (utile en dev/test
avant d'avoir configuré un vrai compte d'envoi)."""

import os
import httpx

RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
EMAIL_FROM = os.environ.get("EMAIL_FROM", "Rift Manager <onboarding@resend.dev>")


async def send_email(to: str, subject: str, html: str) -> bool:
    if not RESEND_API_KEY:
        print(f"[EMAIL NON ENVOYÉ - RESEND_API_KEY absente]\nÀ : {to}\nSujet : {subject}\n{html}\n")
        return True

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
                json={"from": EMAIL_FROM, "to": [to], "subject": subject, "html": html},
            )
            return resp.status_code in (200, 201)
    except Exception as exc:
        print(f"[ERREUR ENVOI EMAIL] {exc}")
        return False
