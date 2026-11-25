"use strict";
// FVPN GUI — Windows 11 Settings style. All privileged work happens in the
// service; this page renders status and forwards input via window.go.main.App.

const $ = (id) => document.getElementById(id);
const api = () => window.go.main.App;

let init = { profiles: [], users: {}, lastProfile: "", locked: false };
let status = { state: "idle" };
let serviceError = "";
let busy = false;           // a user action is in flight
let inlineErr = "";         // error already shown inside the card (avoid duplicates)
let errDismissed = "";      // lastError the user closed
let openId = null;          // expanded profile card
let page = "main";          // main | edit | logs
let editing = null;         // profile being edited (null = new)
let cert = null;            // CheckCert result for the edit form
let chalSince = 0;
const CHAL_TTL = 180;
const cards = new Map();    // profile id -> {root, desc, action, ring, toggle}

const SESSION = ["need_2fa", "connecting", "connected", "disconnecting"];

// Sentence case with Turkish rules (i → İ).
function cap(s) {
  s = String(s || "").replace(/^Error:\s*/, "");
  return s ? s.charAt(0).toLocaleUpperCase("tr-TR") + s.slice(1) : s;
}
function show(id, on) { $(id).hidden = !on; }
function bar(barId, msgId, text) {
  $(msgId).textContent = cap(text);
  show(barId, !!text);
}
function fmtDur(sec) {
  sec = Math.max(0, Math.floor(sec));
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
  return h > 0 ? `${h} sa ${m} dk` : m > 0 ? `${m} dk ${s} sn` : `${s} sn`;
}
function fmtBytes(n) {
  n = n || 0;
  const u = ["bayt", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1).replace(".", ",") : n) + " " + u[i];
}
function parseTime(t) {
  if (!t || t.startsWith("0001")) return 0;
  const v = Date.parse(t);
  return isNaN(v) ? 0 : v;
}
function sessionState() {
  return serviceError ? "idle" : (status.state || "idle");
}
function activeProfile() {
  return SESSION.includes(sessionState()) ? status.profile : null;
}

// ---------- dialog ----------

let dlgResolve = null;
function dialog({ title, text, primary, secondary }) {
  $("dlgTitle").textContent = title;
  $("dlgText").textContent = text;
  $("dlgPrimary").textContent = primary;
  $("dlgSecondary").textContent = secondary || "";
  show("dlgSecondary", !!secondary);
  show("dlg", true);
  $("dlgClose").focus();
  return new Promise((r) => { dlgResolve = r; });
}
function closeDialog(result) {
  show("dlg", false);
  if (dlgResolve) { dlgResolve(result); dlgResolve = null; }
}

// ---------- profile cards ----------

function buildCards() {
  const host = $("profileCards");
  const keep = new Set(init.profiles.map((p) => p.id));
  for (const [id, c] of cards) if (!keep.has(id)) { c.root.remove(); cards.delete(id); }
  for (const p of init.profiles) {
    let c = cards.get(p.id);
    if (!c) {
      const root = $("tplCard").content.firstElementChild.cloneNode(true);
      c = {
        root,
        head: root.querySelector(".exp-head"),
        name: root.querySelector(".pc-name"),
        desc: root.querySelector(".pc-desc"),
        ring: root.querySelector(".pc-ring"),
        action: root.querySelector(".pc-action"),
        toggle: root.querySelector(".pc-toggle"),
      };
      c.toggle.addEventListener("click", () => toggleCard(p.id));
      c.head.addEventListener("click", (e) => { if (!e.target.closest("button")) toggleCard(p.id); });
      c.action.addEventListener("click", () => cardAction(p.id));
      cards.set(p.id, c);
    }
    c.name.textContent = p.name;
    host.append(c.root); // keeps order in sync with init.profiles
  }
  if (openId && !keep.has(openId)) openId = null;
  if (!openId && init.profiles.length === 1) openId = init.profiles[0].id;
}

function toggleCard(id) {
  openId = openId === id ? null : id;
  render();
  if (openId === id) focusNext();
}

function cardAction(id) {
  const st = sessionState();
  if (activeProfile() === id) {
    if (st === "connected" || st === "connecting" || st === "need_2fa") disconnect();
    return;
  }
  // "Bağlan" on a closed card: open it and go to the next empty field.
  openId = id;
  render();
  focusNext();
}

function focusNext() {
  const st = sessionState();
  if (st === "need_2fa") { $("code").focus(); return; }
  if (!$("pLogin").hidden) ($("user").value ? $("pass") : $("user")).focus();
}

function profileById(id) { return init.profiles.find((p) => p.id === id); }

function renderCards() {
  const st = sessionState();
  const act = activeProfile();
  for (const p of init.profiles) {
    const c = cards.get(p.id);
    const mine = act === p.id;
    let desc = p.server, label = "Bağlan", showAction = true, ring = false;
    if (mine) {
      switch (st) {
        case "connected": desc = "Bağlandı"; label = "Bağlantıyı kes"; break;
        case "need_2fa": desc = "Doğrulama kodu bekleniyor"; showAction = false; break;
        case "connecting": desc = cap(status.message || "Bağlanıyor"); label = "İptal"; ring = true; break;
        case "disconnecting": desc = "Bağlantı kesiliyor"; showAction = false; ring = true; break;
      }
    }
    const open = openId === p.id;
    if (!mine && open) showAction = false;          // the form below has its own button
    c.desc.textContent = desc;
    c.action.textContent = label;
    c.action.hidden = !showAction;
    c.action.disabled = busy || !!serviceError || (!!act && !mine);
    c.ring.hidden = !ring;
    c.root.classList.toggle("open", open && panelHasContent(p.id));
  }
}

function panelHasContent(id) {
  const st = sessionState();
  if (activeProfile() === id) return st === "need_2fa" || st === "connected";
  return !activeProfile();   // another profile's session: nothing to show here
}

function renderPanel() {
  const st = sessionState();
  const act = activeProfile();
  const id = openId;
  const p = id && profileById(id);
  const panel = $("panel");
  if (!p || !panelHasContent(id)) { panel.hidden = true; return; }

  const c = cards.get(id);
  if (panel.parentElement !== c.root) c.root.append(panel);
  panel.hidden = false;

  const mine = act === id;
  const idle = !act;
  show("pLogin", idle);
  show("pCode", mine && st === "need_2fa");
  show("pUp", mine && st === "connected");
  show("pManage", idle);

  if (idle) {
    $("pServer").textContent = p.server + (p.realm ? ` · realm ${p.realm}` : "");
    show("btnEditProfile", !init.locked);
    show("btnRemoveProfile", !init.locked);
    $("btnConnect").disabled = busy || !!serviceError;
    if ($("user").dataset.profile !== id) {      // switching cards: load remembered username
      $("user").dataset.profile = id;
      $("user").value = init.users[id] || "";
      $("pass").value = "";
      bar("loginBar", "loginMsg", "");
    }
  }
  if (mine && st === "need_2fa") {
    $("chalMsg").textContent = cap(status.message || "Doğrulama kodunu girin");
    $("btnCode").disabled = busy;
  }
  if (mine && st === "connected") {
    $("upIP").textContent = status.localIp || "-";
    $("upUser").textContent = status.username || "-";
    $("upRoutes").textContent = String(status.routes || 0);
    const dns = status.dnsRules || [];
    $("upDNS").replaceChildren(...dns.map((t) => { const d = document.createElement("div"); d.textContent = t; return d; }));
    if (!dns.length) $("upDNS").textContent = "-";
    $("upRx").textContent = fmtBytes(status.rxBytes);
    $("upTx").textContent = fmtBytes(status.txBytes);
  }
}

// ---------- main render ----------

function render() {
  show("pgMain", page === "main");
  show("pgEdit", page === "edit");
  show("pgLogs", page === "logs");

  const st = sessionState();
  bar("svcBar", "svcMsg", serviceError);

  const lastErr = cap(status.lastError || "");
  const showErr = !serviceError && st === "error" && lastErr && lastErr !== inlineErr && lastErr !== errDismissed;
  bar("errBar", "errMsg", showErr ? lastErr : "");

  show("btnAddProfile", !init.locked);
  $("btnAddProfile").disabled = !!serviceError;

  // 2FA countdown bookkeeping
  if (st === "need_2fa") {
    if (!chalSince) {
      chalSince = Date.now();
      $("code").value = "";
      openId = status.profile;
      setTimeout(() => $("code").focus(), 0);
    }
  } else {
    chalSince = 0;
  }

  renderCards();
  renderPanel();
  tick();
}

function tick() {
  if (sessionState() === "connected") {
    const since = parseTime(status.since);
    $("upFor").textContent = since ? fmtDur((Date.now() - since) / 1000) : "-";
    const exp = parseTime(status.expiresAt);
    if (exp) {
      const at = new Date(exp).toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit" });
      $("upExp").textContent = `${at} (${fmtDur((exp - Date.now()) / 1000)} kaldı)`;
    } else {
      $("upExp").textContent = "-";
    }
  }
  if (sessionState() === "need_2fa" && chalSince) {
    const left = CHAL_TTL - (Date.now() - chalSince) / 1000;
    $("chalLeft").textContent = left > 0 ? `Kalan süre: ${fmtDur(left)}` : "Süre doldu";
  }
}

function onStatus(ev) {
  const prev = sessionState();
  serviceError = ev.serviceError || "";
  if (ev.status) status = ev.status;
  // open the card once when the session comes up; the user may close it
  if (prev !== "connected" && sessionState() === "connected") openId = status.profile;
  render();
}

async function guarded(fn) {
  if (busy) return;
  busy = true;
  render();
  try {
    const s = await fn();
    if (s) status = s;
  } finally {
    busy = false;
    render();
  }
}

// ---------- connect / 2FA / disconnect ----------

function connect() {
  const profile = openId;
  const user = $("user").value.trim();
  const pass = $("pass").value;
  if (!profile) return;
  if (!user || !pass) {
    inlineErr = cap("Kullanıcı adı ve parola gerekli");
    bar("loginBar", "loginMsg", inlineErr);
    return;
  }
  inlineErr = "";
  errDismissed = "";
  bar("loginBar", "loginMsg", "");
  guarded(async () => {
    try {
      const s = await api().Connect(profile, user, pass);
      init.users[profile] = user;
      init.lastProfile = profile;
      return s;
    } catch (e) {
      inlineErr = cap(String(e));
      bar("loginBar", "loginMsg", inlineErr);
    } finally {
      $("pass").value = "";   // never keep the password around
    }
  });
}

function submitCode() {
  const code = $("code").value.trim();
  if (!code) return;
  bar("codeBar", "codeMsg", "");
  guarded(async () => {
    try {
      return await api().Submit2FA(code);
    } catch (e) {
      // the session is gone (state=error); the page InfoBar shows why
      errDismissed = "";
    } finally {
      $("code").value = "";
    }
  });
}

function disconnect() {
  guarded(() => api().Disconnect().catch(() => null));
}

// ---------- profile edit ----------

function openEdit(p) {
  editing = p || null;
  cert = null;
  $("editTitle").textContent = p ? p.name : "Profil ekle";
  $("eName").value = p ? p.name : "";
  $("eServer").value = p ? p.server : "";
  $("eRealm").value = p ? (p.realm || "") : "";
  $("ePin").checked = false;
  certView("none");
  bar("editBar", "editMsg", "");
  page = "edit";
  render();
  $("eName").focus();
}

function certView(mode) {
  const sameServer = editing && $("eServer").value.trim() === editing.server;
  show("certRing", mode === "checking");
  show("certDetails", mode === "checked");
  $("btnCheckCert").disabled = mode === "checking";
  const t = $("certTitle"), d = $("certDesc");
  if (mode === "checking") { t.textContent = "Kontrol ediliyor…"; d.textContent = ""; return; }
  if (mode === "checked") {
    t.textContent = cert.verified ? "Güvenilir" : "Doğrulanamadı";
    d.textContent = cert.verified ? "Windows bu sertifikayı doğruladı" : "Parmak izini güvendiğiniz bir kaynakla karşılaştırın";
    $("certSubject").textContent = cert.subject;
    $("certIssuer").textContent = cert.issuer;
    $("certExpiry").textContent = cert.notAfter;
    $("certFp").textContent = cert.fingerprint;
    show("pinRow", !cert.verified);
    return;
  }
  if (sameServer && editing.trustedCert) {
    t.textContent = "Sabitlenmiş sertifika";
    d.textContent = editing.trustedCert.slice(0, 16) + "…";
  } else if (sameServer) {
    t.textContent = "Windows doğrulaması";
    d.textContent = "Sunucuyu değiştirirseniz yeniden kontrol edin";
  } else {
    t.textContent = "Kontrol edilmedi";
    d.textContent = "Kaydetmeden önce sertifikayı kontrol edin";
  }
}

async function checkCert() {
  const server = $("eServer").value.trim();
  if (!server) { bar("editBar", "editMsg", "Sunucu adresi gerekli"); return; }
  bar("editBar", "editMsg", "");
  certView("checking");
  try {
    cert = await api().CheckCert(server);
    $("eServer").value = cert.server;
    $("ePin").checked = false;
    certView("checked");
  } catch (e) {
    cert = null;
    certView("none");
    bar("editBar", "editMsg", String(e));
  }
}

async function saveProfile() {
  const name = $("eName").value.trim();
  const server = $("eServer").value.trim();
  if (!name) { bar("editBar", "editMsg", "Bağlantı adı gerekli"); return; }
  if (!server) { bar("editBar", "editMsg", "Sunucu adresi gerekli"); return; }

  // Pin decision: checked now → pin only an untrusted cert the user accepted;
  // not checked → keep the existing setting if the server did not change.
  let pin = "";
  const sameServer = editing && server === editing.server;
  if (cert) {
    if (!cert.verified) {
      if (!$("ePin").checked) { bar("editBar", "editMsg", "Sertifika doğrulanamadı. Kaydetmek için \"Bu sertifikaya güven\" seçeneğini işaretleyin"); return; }
      pin = cert.fingerprint;
    }
  } else if (sameServer) {
    pin = editing.trustedCert || "";
  } else {
    bar("editBar", "editMsg", "Önce sunucu sertifikasını kontrol edin");
    return;
  }

  $("btnSaveProfile").disabled = true;
  bar("editBar", "editMsg", "");
  try {
    const id = await api().SaveProfile({
      id: editing ? editing.id : "",
      name,
      server: cert ? cert.server : server,
      realm: $("eRealm").value.trim(),
      trustedCert: pin,
    });
    await reloadProfiles();
    openId = id;
    page = "main";
    render();
    focusNext();
  } catch (e) {
    bar("editBar", "editMsg", String(e));
  } finally {
    $("btnSaveProfile").disabled = false;
  }
}

async function removeProfile() {
  const p = profileById(openId);
  if (!p) return;
  const r = await dialog({
    title: "Profil kaldırılsın mı?",
    text: `"${p.name}" bağlantı profili bu bilgisayardan kaldırılacak.`,
    primary: "Kaldır",
  });
  if (r !== "primary") return;
  try {
    await api().DeleteProfile(p.id);
    openId = null;
    await reloadProfiles();
  } catch (e) {
    inlineErr = cap(String(e));
    bar("loginBar", "loginMsg", inlineErr);
  }
  render();
}

async function reloadProfiles() {
  const r = await api().Profiles();
  init.profiles = r.profiles || [];
  init.locked = !!r.locked;
  buildCards();
}

// ---------- logs ----------

async function loadLogs() {
  try {
    const lines = await api().Logs();
    $("logs").textContent = (lines || []).join("\n") || "Kayıt yok.";
  } catch (e) {
    $("logs").textContent = cap(String(e));
  }
  $("logs").scrollTop = $("logs").scrollHeight;
}

// Copies the connection properties as "Etiket: değer" lines.
async function copyProps() {
  const lines = [];
  for (const tr of $("upTable").querySelectorAll("tr")) {
    const k = tr.querySelector("th").textContent;
    const cell = tr.querySelector("td");
    const parts = cell.children.length ? [...cell.children].map((d) => d.textContent) : [cell.textContent];
    lines.push(`${k}: ${parts.join("; ")}`);
  }
  try {
    await navigator.clipboard.writeText(lines.join("\n"));
    $("btnCopyProps").textContent = "Kopyalandı";
    setTimeout(() => { $("btnCopyProps").textContent = "Kopyala"; }, 1500);
  } catch (e) { /* clipboard unavailable */ }
}

async function copyLogs() {
  try {
    await navigator.clipboard.writeText($("logs").textContent);
    $("btnLogsCopy").textContent = "Kopyalandı";
    setTimeout(() => { $("btnLogsCopy").textContent = "Kopyala"; }, 1500);
  } catch (e) { /* clipboard unavailable: ignore */ }
}

// ---------- boot ----------

function setAutostartUI(on) {
  $("autostart").checked = !!on;
  $("autostartText").textContent = on ? "Açık" : "Kapalı";
}

async function boot() {
  init = await api().Init();
  init.profiles = init.profiles || [];
  init.users = init.users || {};
  if (init.mica) document.body.classList.add("mica");
  if (init.accent) {
    document.documentElement.style.setProperty("--accent-l", init.accent.light);
    document.documentElement.style.setProperty("--accent-d", init.accent.dark);
  }
  $("ver").textContent = "FVPN " + init.version;
  setAutostartUI(await api().GetAutostart());
  if (init.profiles.some((p) => p.id === init.lastProfile)) openId = init.lastProfile;
  buildCards();
  if (init.error) serviceError = init.error;
  render();
  focusNext();
}

function wire() {
  $("btnConnect").addEventListener("click", connect);
  $("user").addEventListener("keydown", (e) => { if (e.key === "Enter") $("pass").focus(); });
  $("pass").addEventListener("keydown", (e) => { if (e.key === "Enter") connect(); });
  $("btnCode").addEventListener("click", submitCode);
  $("code").addEventListener("keydown", (e) => { if (e.key === "Enter") submitCode(); });
  $("code").addEventListener("input", () => { $("code").value = $("code").value.replace(/\s+/g, ""); });
  $("btnCancelCode").addEventListener("click", disconnect);
  $("errClose").addEventListener("click", () => { errDismissed = cap(status.lastError || ""); render(); });

  $("btnAddProfile").addEventListener("click", () => openEdit(null));
  $("btnEditProfile").addEventListener("click", () => openEdit(profileById(openId)));
  $("btnRemoveProfile").addEventListener("click", removeProfile);
  $("crumbEdit").addEventListener("click", () => { page = "main"; render(); });
  $("btnCancelEdit").addEventListener("click", () => { page = "main"; render(); });
  $("eServer").addEventListener("input", () => { cert = null; certView("none"); });
  $("btnCheckCert").addEventListener("click", checkCert);
  $("btnSaveProfile").addEventListener("click", saveProfile);

  $("btnLogs").addEventListener("click", () => { page = "logs"; render(); loadLogs(); });
  $("crumbLogs").addEventListener("click", () => { page = "main"; render(); });
  $("btnLogsRefresh").addEventListener("click", loadLogs);
  $("btnLogsCopy").addEventListener("click", copyLogs);
  $("btnCopyProps").addEventListener("click", copyProps);

  $("autostart").addEventListener("change", async (e) => {
    const want = e.target.checked;
    setAutostartUI(want);
    try { await api().SetAutostart(want); } catch (err) { setAutostartUI(!want); }
  });
  window.runtime.EventsOn("autostart", setAutostartUI);

  // dialog
  $("dlgPrimary").addEventListener("click", () => closeDialog("primary"));
  $("dlgSecondary").addEventListener("click", () => closeDialog("secondary"));
  $("dlgClose").addEventListener("click", () => closeDialog("close"));
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("dlg").hidden) closeDialog("close"); });

  // tray "Çıkış" while a session is active
  window.runtime.EventsOn("close-requested", async () => {
    const r = await dialog({
      title: "VPN bağlantısı açık",
      text: "FVPN'den çıksanız da bağlantı açık kalabilir.",
      primary: "Bağlantıyı kes ve çık",
      secondary: "Bağlı kalsın, çık",
    });
    if (r === "primary") api().Quit(true);
    else if (r === "secondary") api().Quit(false);
  });

  // tray "Bağlan…"
  window.runtime.EventsOn("focus-login", () => {
    page = "main";
    if (!openId && init.profiles.length) openId = init.lastProfile || init.profiles[0].id;
    render();
    focusNext();
  });

  window.runtime.EventsOn("status", onStatus);
  setInterval(tick, 1000);
}

window.addEventListener("DOMContentLoaded", () => {
  wire();
  boot().catch((e) => { serviceError = String(e); render(); });
});
