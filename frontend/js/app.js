// ---------- Configuration ----------
const API_BASE = "https://api.rift-manager.pro";

// ---------- Gestion du token ----------

function getToken() {
  return localStorage.getItem("rift_token");
}

function setToken(token) {
  localStorage.setItem("rift_token", token);
}

function clearToken() {
  localStorage.removeItem("rift_token");
}

function isLoggedIn() {
  return !!getToken();
}

function logout() {
  clearToken();
  window.location.href = "/login.html";
}

// Appel API authentifié, gère automatiquement le header Authorization
async function apiFetch(path, options = {}) {
  const headers = Object.assign(
    { "Content-Type": "application/json" },
    options.headers || {}
  );
  const token = getToken();
  if (token) headers["Authorization"] = "Bearer " + token;

  const resp = await fetch(API_BASE + path, { ...options, headers });

  if (resp.status === 401) {
    clearToken();
    if (!window.location.pathname.includes("login") && !window.location.pathname.includes("signup")) {
      window.location.href = "/login.html";
    }
    throw new Error("Session expirée, merci de te reconnecter");
  }

  return resp;
}

// Protège une page : redirige vers /login.html si non connecté
function requireAuth() {
  if (!isLoggedIn()) {
    window.location.href = "/login.html";
  }
}

// ---------- Glyphe de marque (ligne de faille) ----------

const FAULT_GLYPH = `
  <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M2 18 L8 13 L11 17 L14 7 L17 12 L22 5" stroke="var(--hazard)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>
`;

// ---------- Navigation injectée (en-tête de dossier) ----------

function renderNavbar() {
  const placeholder = document.getElementById("navbar-placeholder");
  if (!placeholder) return;

  const loggedIn = isLoggedIn();
  const currentPage = window.location.pathname.split("/").pop() || "index.html";

  const navLink = (href, label) =>
    `<a href="${href}" class="${currentPage === href ? 'active' : ''}">${label}</a>`;

  let links = "";
  let cta = "";

  if (loggedIn) {
    links = [
      navLink("dashboard.html", "Scanner"),
      navLink("history.html", "Historique"),
      navLink("pricing.html", "Tarifs"),
      navLink("profile.html", "Profil"),
      navLink("settings.html", "Paramètres"),
    ].join("");
    cta = `<a href="#" onclick="logout(); return false;" class="nav-cta" style="background:transparent; color:var(--muted) !important; border:1px solid var(--hairline); box-shadow:none;">Déconnexion</a>`;
  } else {
    links = [
      navLink("index.html", "Accueil"),
      navLink("pricing.html", "Tarifs"),
    ].join("");
    cta = `<a href="login.html" class="nav-cta">Connexion</a>`;
  }

  placeholder.innerHTML = `
    <div class="navbar">
      <a href="${loggedIn ? 'dashboard.html' : 'index.html'}" class="brand">${FAULT_GLYPH} Rift Manager</a>
      <nav>${links}${cta}</nav>
    </div>
  `;
}

document.addEventListener("DOMContentLoaded", renderNavbar);

// ---------- Footer injecté automatiquement (pied de dossier) ----------

function renderFooter() {
  const footer = document.createElement("footer");
  footer.innerHTML = `
    Rift Manager // rift-manager.pro<br>
    <span style="font-size:0.85em; text-transform:none; letter-spacing:0;">
      <a href="legal.html">Mentions légales</a> ·
      <a href="terms.html">CGU</a> ·
      <a href="privacy.html">Confidentialité</a>
    </span>
  `;
  document.body.appendChild(footer);
}

document.addEventListener("DOMContentLoaded", renderFooter);

// =========================================================================
// Helpers de rendu partagés pour les résultats de scan
// (utilisés par dashboard.html, scan-detail.html, history.html)
// =========================================================================

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

const CHECK_LABELS = [
  ["https_redirect", "Redirection HTTPS"],
  ["ssl_certificate", "Certificat SSL"],
  ["exposed_files", "Fichiers sensibles"],
  ["security_headers", "Headers de sécurité"],
  ["spf_dmarc", "SPF / DMARC"],
  ["cookies", "Cookies"],
  ["cors", "Configuration CORS"],
  ["tls_version", "Versions TLS"],
  ["server_info_disclosure", "Fuite d'info serveur"],
  ["dangerous_http_methods", "Méthodes HTTP dangereuses"],
];

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatDateFr(isoString) {
  const d = new Date(isoString);
  return d.toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit", year: "numeric" }) +
    " à " + d.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
}

function scoreZone(score) {
  if (score >= 75) return "signal";
  if (score >= 40) return "hazard";
  return "fault";
}

function scoreColor(score) {
  return `var(--${scoreZone(score)})`;
}

// Cadran d'intégrité — élément signature : un demi-cercle à 3 zones fixes
// (fault / hazard / signal) avec une aiguille qui pivote selon le score.
function buildGauge(score, grade) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const angleDeg = 180 - (clamped / 100) * 180;
  const rad = (angleDeg * Math.PI) / 180;
  const needleLen = 72;
  const tipX = (110 + needleLen * Math.cos(rad)).toFixed(1);
  const tipY = (140 - needleLen * Math.sin(rad)).toFixed(1);
  const zone = scoreZone(clamped);

  return `
    <div class="gauge">
      <svg viewBox="0 0 220 150" class="gauge-svg" aria-hidden="true">
        <path d="M20,140 A90,90 0 0,1 82.2,54.4" class="gauge-arc fault"></path>
        <path d="M82.2,54.4 A90,90 0 0,1 173.6,76.4" class="gauge-arc hazard"></path>
        <path d="M173.6,76.4 A90,90 0 0,1 200,140" class="gauge-arc signal"></path>
        <line x1="110" y1="140" x2="${tipX}" y2="${tipY}" class="gauge-needle"></line>
        <circle cx="110" cy="140" r="5" class="gauge-pivot"></circle>
      </svg>
      <div class="gauge-readout">
        <span class="gauge-number zone-${zone}">${clamped}</span>
        <span class="gauge-suffix">/100</span>
      </div>
      <div class="gauge-stamp">${escapeHtml(grade)}</div>
    </div>
  `;
}

function buildScoreCard(target, score, grade, dateLabel) {
  return `
    <div class="score-card">
      ${buildGauge(score, grade)}
      <div class="score-meta">
        <div class="score-target">${escapeHtml(target)}</div>
        ${dateLabel ? `<div class="score-date">${escapeHtml(dateLabel)}</div>` : ""}
      </div>
    </div>
  `;
}

function renderCheck(label, passed, detail) {
  return `
    <div class="check">
      <div>
        <div class="label">${escapeHtml(label)}</div>
        <div class="status ${passed ? 'pass' : 'fail'}">${escapeHtml(detail)}</div>
      </div>
      <div style="font-size:1.2rem;">${passed ? '✓' : '!'}</div>
    </div>
  `;
}

function renderChecksSummary(checks) {
  return CHECK_LABELS.map(([key, label]) => {
    const c = checks[key];
    if (!c) return "";
    if (key === "security_headers") {
      return renderCheck(label, c.points === c.max_points, `${c.points}/${c.max_points} points`);
    }
    return renderCheck(label, c.passed, c.detail);
  }).join("");
}

function renderVuln(v) {
  return `
    <div class="vuln-card ${v.severity}">
      <div class="vuln-header">
        <div class="vuln-title">${escapeHtml(v.title)}</div>
        <div class="badge ${v.severity}">${escapeHtml(v.severity_label)}</div>
      </div>
      <div class="vuln-body">
        <div class="vuln-section"><strong>Risque</strong><br>${escapeHtml(v.risk)}</div>
        <div class="vuln-section"><strong>Recommandation</strong><br>${escapeHtml(v.recommendation)}</div>
        ${v.evidence ? `<div class="vuln-evidence">${escapeHtml(v.evidence)}</div>` : ""}
      </div>
    </div>
  `;
}

function renderVulnsSection(vulns) {
  if (!vulns || vulns.length === 0) {
    return `<div class="no-vulns">Aucune vulnérabilité détectée par ce scan</div>`;
  }
  const sorted = [...vulns].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  return `
    <div class="section-title">${sorted.length} vulnérabilité(s) détectée(s)</div>
    ${sorted.map(renderVuln).join("")}
  `;
}

// Assemble le rendu complet d'un résultat de scan (carte + contrôles + vulns)
function renderScanResult(data, dateLabel) {
  return `
    ${buildScoreCard(data.target, data.score, data.grade, dateLabel)}
    <div class="section-title">Résumé des contrôles</div>
    ${renderChecksSummary(data.checks)}
    ${renderVulnsSection(data.vulnerabilities)}
  `;
}
