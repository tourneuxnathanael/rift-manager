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

// ---------- Navigation injectée ----------

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
    cta = `<a href="#" onclick="logout(); return false;" class="nav-cta" style="background:transparent; color:var(--muted) !important; border:1px solid var(--border);">Déconnexion</a>`;
  } else {
    links = [
      navLink("index.html", "Accueil"),
      navLink("pricing.html", "Tarifs"),
    ].join("");
    cta = `<a href="login.html" class="nav-cta">Connexion</a>`;
  }

  placeholder.innerHTML = `
    <div class="navbar">
      <a href="${loggedIn ? 'dashboard.html' : 'index.html'}" class="brand">🔒 Rift Manager</a>
      <nav>${links}${cta}</nav>
    </div>
  `;
}

document.addEventListener("DOMContentLoaded", renderNavbar);

// ---------- Footer injecté automatiquement (liens légaux) ----------

function renderFooter() {
  const footer = document.createElement("footer");
  footer.innerHTML = `
    Rift Manager — rift-manager.pro<br>
    <span style="font-size:0.8rem;">
      <a href="legal.html">Mentions légales</a> ·
      <a href="terms.html">CGU</a> ·
      <a href="privacy.html">Confidentialité</a>
    </span>
  `;
  document.body.appendChild(footer);
}

document.addEventListener("DOMContentLoaded", renderFooter);
