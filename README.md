# Rift Manager — Security Scanner MVP

Scanner de sécurité web léger, conçu pour les fondateurs de SaaS / petites structures qui veulent un état des lieux rapide de leur exposition.

## Checks inclus

- **Redirection HTTPS** : vérifie que le HTTP redirige bien vers HTTPS
- **Headers de sécurité** : HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
- **Certificat SSL** : validité + nombre de jours avant expiration
- **Fichiers sensibles exposés** : .env, .git/config, backups, etc.

## Lancer le backend

```bash
cd backend
python -m venv venv
source venv/bin/activate  # ou venv\Scripts\activate sur Windows
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

L'API tourne sur `http://localhost:8000`. Doc interactive : `http://localhost:8000/docs`

## Lancer le frontend

Simple fichier statique, à ouvrir directement ou servir via :

```bash
cd frontend
python -m http.server 5500
```

Puis ouvrir `http://localhost:5500`.

⚠️ Pense à adapter `API_URL` dans `index.html` si tu déploies le backend ailleurs qu'en local.

## Prochaines étapes possibles

- [ ] Ajouter des checks : CORS misconfig, cookies sans `Secure`/`HttpOnly`, DNS (SPF/DMARC/DKIM), ports ouverts courants
- [ ] Génération de rapport PDF téléchargeable
- [ ] Système de scan récurrent (monitoring hebdo) → modèle d'abonnement
- [ ] Page de capture d'email avant d'afficher le score complet (lead magnet)
- [ ] Authentification + historique de scans par compte
- [ ] Déploiement (Render/Railway pour le backend, Vercel/Netlify pour le frontend)

## Pistes business model

- **Freemium** : scan basique gratuit, rapport détaillé + PDF payant (one-shot, ~15-29€)
- **Abonnement** : monitoring mensuel automatique avec alertes par email (~9-19€/mois)
- **Lead magnet B2B** : scan gratuit comme outil d'acquisition pour vendre du conseil sécu en prestation derrière
