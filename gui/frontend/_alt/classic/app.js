"use strict";
// FVPN GUI — classic Win32 look (WireGuard-like). All privileged work happens
// in the service; this page renders status and forwards input via
// window.go.main.App.

const $ = (id) => document.getElementById(id);
const api = () => window.go.main.App;

let init = { profiles: [], users: {}, lastProfile: "", locked: false };
let status = { state: "idle" };
let serviceError = "";
let busy = false;
let selId = null;          // selected profile in the list
let mode = "view";         // view | edit
let editing = null;        // profile being edited (null = new)
let cert = null;           // CheckCert result
let formErr = "";          // error from the last action, shown in the group box
let chalSince = 0;
const CHAL_TTL = 180;
const SESSION = ["need_2fa", "connecting", "connected", "disconnecting"];

function cap(s) {
  s = String(s || "").replace(/^Error:\s*/, "");
  return s ? s.charAt(0).toLocaleUpperCase("tr-TR") + s.slice(1) : s;
}
function show(id, on) { $(id).hidden = !on; }
function line(id, text) { $(id).textContent = cap(text); show(id, !!text); }
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
function st() { return serviceError ? "idle" : (status.state || "idle"); }
function activeId() { return SESSION.includes(st()) ? status.profile : null; }
function profileById(id) { return init.profiles.find((p) => p.id === id); }

// ---------- message box ----------

let dlgResolve = null;
function msgbox({ title, text, primary, secondary }) {
  $("dlgTitle").textContent = title;
  $("dlgText").textContent = text;
  $("dlgPrimary").textContent = primary;
  $("dlgSecondary").textContent = secondary || "";
  show("dlgSecondary", !!secondary);
  show("dlg", true);
  $("dlgClose").focus();
  return new Promise((r) => { dlgResolve = r; });
}
function closeMsg(r) {
  show("dlg", false);
  if (dlgResolve) { dlgResolve(r); dlgResolve = null; }
}

// ---------- list ----------

function renderList() {
  const act = activeId();
  const list = $("list");
  list.replaceChildren(...init.profiles.map((p) => {
    const it = document.createElement("div");
    it.className = "item" + (p.id === selId ? " sel" : "");
    it.setAttribute("role", "option");
    const dot = document.createElement("span");
    dot.className = "dot" + dotClass(p.id === act);
    const name = document.createElement("span");
    name.className = "name";
    name.textContent = p.name;
    it.append(dot, name);
    it.addEventListener("click", () => select(p.id));
    return it;
  }));
  $("btnDel").disabled = init.locked || !selId || selId === act || mode === "edit";
  $("btnAdd").disabled = init.locked || mode === "edit" || !!serviceError;
}

function dotClass(mine) {
  if (!mine) return "";
  return st() === "connected" ? " on" : " busy";
}

function select(id) {
  if (mode === "edit") return;
  if (selId !== id) { selId = id; formErr = ""; loadUser(); }
  render();
}

function loadUser() {
  $("user").value = (selId && init.users[selId]) || "";
  $("pass").value = "";
}

// ---------- detail ----------

function renderView() {
  const p = profileById(selId);
  show("vEmpty", !p && mode === "view" && !serviceError);
  show("vView", !!p && mode === "view");
  show("vEdit", mode === "edit");
  if (!p || mode !== "view") return;

  const s = st();
  const act = activeId();
  const mine = act === p.id;
  const other = act && !mine;
  const idle = !act;

  $("gTitle").textContent = "Bağlantı: " + p.name;
  $("vServer").textContent = p.server;
  $("vRealm").textContent = p.realm || "";
  show("rRealm", !!p.realm);

  let text = "Bağlı değil", dot = "";
  if (mine) {
    switch (s) {
      case "need_2fa": text = "Doğrulama kodu bekleniyor"; dot = " busy"; break;
      case "connecting": text = "Bağlanıyor (" + cap(status.message || "") + ")"; dot = " busy"; break;
      case "connected": text = "Bağlı"; dot = " on"; break;
      case "disconnecting": text = "Bağlantı kesiliyor"; dot = " busy"; break;
    }
  } else if (other) {
    text = "Bağlı değil (başka bir bağlantı etkin)";
  }
  $("stText").textContent = text;
  $("stDot").className = "dot" + dot;

  const lastErr = s === "error" && status.profile === p.id && status.lastError && cap(status.lastError) !== formErr;
  $("vLastErr").textContent = lastErr ? cap(status.lastError) : "";
  show("rLastErr", !!lastErr);

  const login = idle;
  show("rUser", login); show("rPass", login);
  const code = mine && s === "need_2fa";
  show("rChal", code); show("rCode", code); show("rChalLeft", code);
  if (code) $("chalMsg").textContent = cap(status.message || "Doğrulama kodunu girin");
  const up = mine && s === "connected";
  show("rIP", up); show("rUpUser", up); show("rFor", up);
  show("gTunnel", up);
  show("btnCopy", up);
  if (up) {
    $("upIP").textContent = status.localIp || "-";
    $("upUser").textContent = status.username || "-";
    $("upRoutes").textContent = String(status.routes || 0);
    const dns = status.dnsRules || [];
    $("upDNS").replaceChildren(...dns.map((t) => { const d = document.createElement("div"); d.textContent = t; return d; }));
    if (!dns.length) $("upDNS").textContent = "-";
    $("upXfer").textContent = `${fmtBytes(status.rxBytes)} alındı, ${fmtBytes(status.txBytes)} gönderildi`;
  }

  // buttons
  const pb = $("btnPrimary"), sb = $("btnSecondary");
  sb.hidden = true;
  pb.disabled = busy || !!serviceError;
  if (idle) {
    pb.textContent = "Bağlan";
  } else if (code) {
    pb.textContent = "Doğrula";
    sb.textContent = "İptal"; sb.hidden = false; sb.disabled = busy;
  } else if (mine && s === "connecting") {
    pb.textContent = "İptal";
  } else if (mine) {
    pb.textContent = "Bağlantıyı kes";
    pb.disabled = pb.disabled || s === "disconnecting";
  } else {
    pb.textContent = "Bağlan";
    pb.disabled = true;
  }
  line("formErr", formErr);
  $("btnEdit").hidden = init.locked;
  $("btnEdit").disabled = mine;
}

function render() {
  line("svcErr", serviceError ? "Servise bağlanılamıyor: " + serviceError : "");
  const s = st();
  if (s === "need_2fa") {
    if (!chalSince) {
      chalSince = Date.now();
      $("code").value = "";
      if (mode === "view") { selId = status.profile; setTimeout(() => $("code").focus(), 0); }
    }
  } else {
    chalSince = 0;
  }
  renderList();
  renderView();
  tick();
}

function tick() {
  if (st() === "connected") {
    const since = parseTime(status.since);
    $("upFor").textContent = since ? fmtDur((Date.now() - since) / 1000) : "-";
    const exp = parseTime(status.expiresAt);
    $("upExp").textContent = exp
      ? `${new Date(exp).toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit" })} (${fmtDur((exp - Date.now()) / 1000)} kaldı)`
      : "-";
  }
  if (st() === "need_2fa" && chalSince) {
    const left = CHAL_TTL - (Date.now() - chalSince) / 1000;
    $("chalLeft").textContent = left > 0 ? `Kalan süre: ${fmtDur(left)}` : "Süre doldu";
  }
}

function onStatus(ev) {
  serviceError = ev.serviceError || "";
  if (ev.status) status = ev.status;
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

// ---------- actions ----------

function primary() {
  const s = st();
  const mine = activeId() === selId;
  if (!activeId()) return connect();
  if (mine && s === "need_2fa") return submitCode();
  if (mine) return disconnect();
}

function connect() {
  const user = $("user").value.trim();
  const pass = $("pass").value;
  if (!selId) return;
  if (!user) { formErr = "Kullanıcı adını girin"; render(); $("user").focus(); return; }
  if (!pass) { formErr = "Parolayı girin"; render(); $("pass").focus(); return; }
  formErr = "";
  const id = selId;
  guarded(async () => {
    try {
      const s = await api().Connect(id, user, pass);
      init.users[id] = user;
      init.lastProfile = id;
      return s;
    } catch (e) {
      formErr = cap(String(e));
    } finally {
      $("pass").value = "";
    }
  });
}

function submitCode() {
  const code = $("code").value.trim();
  if (!code) { $("code").focus(); return; }
  formErr = "";
  guarded(async () => {
    try {
      return await api().Submit2FA(code);
    } catch (e) {
      formErr = cap(String(e));
    } finally {
      $("code").value = "";
    }
  });
}

function disconnect() {
  formErr = "";
  guarded(() => api().Disconnect().catch(() => null));
}

// ---------- edit ----------

function openEdit(p) {
  editing = p || null;
  cert = null;
  mode = "edit";
  $("eTitle").textContent = p ? "Profil düzenle" : "Profil ekle";
  $("eName").value = p ? p.name : "";
  $("eServer").value = p ? p.server : "";
  $("eRealm").value = p ? (p.realm || "") : "";
  $("ePin").checked = false;
  certView("none");
  line("editErr", "");
  render();
  $("eName").focus();
}

function closeEdit() {
  mode = "view";
  render();
}

function certView(m) {
  const same = editing && $("eServer").value.trim() === editing.server;
  const checked = m === "checked";
  for (const id of ["rCertSub", "rCertIss", "rCertExp", "rCertFp"]) show(id, checked);
  show("rPin", checked && !cert.verified);
  $("btnCheckCert").disabled = m === "checking";
  const s = $("certState");
  s.className = "";
  if (m === "checking") { s.textContent = "Kontrol ediliyor…"; return; }
  if (checked) {
    s.textContent = cert.verified ? "Windows tarafından doğrulandı" : "Doğrulanamadı";
    s.className = cert.verified ? "" : "err-text";
    $("certSubject").textContent = cert.subject;
    $("certIssuer").textContent = cert.issuer;
    $("certExpiry").textContent = cert.notAfter;
    $("certFp").textContent = cert.fingerprint;
    return;
  }
  if (same && editing.trustedCert) s.textContent = "Sabitlenmiş (" + editing.trustedCert.slice(0, 12) + "…)";
  else if (same) s.textContent = "Windows doğrulaması";
  else s.textContent = "Kontrol edilmedi";
}

async function checkCert() {
  const server = $("eServer").value.trim();
  if (!server) { line("editErr", "Sunucu adresini girin"); return; }
  line("editErr", "");
  certView("checking");
  try {
    cert = await api().CheckCert(server);
    $("eServer").value = cert.server;
    $("ePin").checked = false;
    certView("checked");
  } catch (e) {
    cert = null;
    certView("none");
    line("editErr", String(e));
  }
}

async function save() {
  const name = $("eName").value.trim();
  const server = $("eServer").value.trim();
  if (!name) { line("editErr", "Profil adını girin"); return; }
  if (!server) { line("editErr", "Sunucu adresini girin"); return; }
  let pin = "";
  const same = editing && server === editing.server;
  if (cert) {
    if (!cert.verified) {
      if (!$("ePin").checked) { line("editErr", "Sertifika doğrulanamadı. Kaydetmek için \"Bu sertifikaya güven\" kutusunu işaretleyin."); return; }
      pin = cert.fingerprint;
    }
  } else if (same) {
    pin = editing.trustedCert || "";
  } else {
    line("editErr", "Önce sunucu sertifikasını kontrol edin.");
    return;
  }
  $("btnSave").disabled = true;
  line("editErr", "");
  try {
    const id = await api().SaveProfile({
      id: editing ? editing.id : "",
      name,
      server: cert ? cert.server : server,
      realm: $("eRealm").value.trim(),
      trustedCert: pin,
    });
    await reloadProfiles();
    selId = id;
    loadUser();
    mode = "view";
    render();
    ($("user").value ? $("pass") : $("user")).focus();
  } catch (e) {
    line("editErr", String(e));
  } finally {
    $("btnSave").disabled = false;
  }
}

async function remove() {
  const p = profileById(selId);
  if (!p) return;
  const r = await msgbox({ title: "FVPN", text: `"${p.name}" profili silinsin mi?`, primary: "Sil" });
  if (r !== "primary") return;
  try {
    await api().DeleteProfile(p.id);
    await reloadProfiles();
    selId = init.profiles.length ? init.profiles[0].id : null;
    loadUser();
  } catch (e) {
    formErr = cap(String(e));
  }
  render();
}

async function reloadProfiles() {
  const r = await api().Profiles();
  init.profiles = r.profiles || [];
  init.locked = !!r.locked;
}

// ---------- log ----------

function showTab(log) {
  $("tabBtnConn").classList.toggle("sel", !log);
  $("tabBtnLog").classList.toggle("sel", log);
  show("tabConn", !log);
  show("tabLog", log);
  if (log) loadLogs();
}

let logLines = [];
async function loadLogs() {
  try {
    logLines = (await api().Logs()) || [];
  } catch (e) {
    logLines = [cap(String(e))];
  }
  $("logRows").replaceChildren(...logLines.map((l) => {
    const tr = document.createElement("tr");
    const t = document.createElement("td");
    const m = document.createElement("td");
    const hasTime = /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d /.test(l);
    t.textContent = hasTime ? l.slice(0, 19) : "";
    m.textContent = hasTime ? l.slice(20) : l.trim();
    tr.append(t, m);
    return tr;
  }));
  const v = document.querySelector(".logview");
  if (v) v.scrollTop = v.scrollHeight;
}

async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    const old = btn.textContent;
    btn.textContent = "Kopyalandı";
    setTimeout(() => { btn.textContent = old; }, 1500);
  } catch (e) { /* clipboard unavailable */ }
}

function propsText() {
  const p = profileById(selId);
  const dns = [...$("upDNS").children].map((d) => d.textContent).join("; ") || $("upDNS").textContent;
  return [
    `Bağlantı: ${p ? p.name : ""}`,
    `Sunucu: ${p ? p.server : ""}`,
    `IPv4 adresi: ${$("upIP").textContent}`,
    `Kullanıcı: ${$("upUser").textContent}`,
    `Bağlantı süresi: ${$("upFor").textContent}`,
    `Rotalar: ${$("upRoutes").textContent}`,
    `DNS sunucuları: ${dns}`,
    `Oturum sonu: ${$("upExp").textContent}`,
    `Aktarım: ${$("upXfer").textContent}`,
  ].join("\n");
}

// ---------- boot ----------

async function boot() {
  init = await api().Init();
  init.profiles = init.profiles || [];
  init.users = init.users || {};
  $("ver").textContent = "FVPN " + init.version;
  $("autostart").checked = await api().GetAutostart();
  selId = init.profiles.some((p) => p.id === init.lastProfile) ? init.lastProfile : (init.profiles[0] || {}).id || null;
  loadUser();
  if (init.error) serviceError = init.error;
  render();
  if (selId) ($("user").value ? $("pass") : $("user")).focus();
}

function wire() {
  $("tabBtnConn").addEventListener("click", () => showTab(false));
  $("tabBtnLog").addEventListener("click", () => showTab(true));

  $("list").addEventListener("keydown", (e) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const i = init.profiles.findIndex((p) => p.id === selId);
    const n = init.profiles[Math.min(init.profiles.length - 1, Math.max(0, i + (e.key === "ArrowDown" ? 1 : -1)))];
    if (n) select(n.id);
  });
  $("btnAdd").addEventListener("click", () => openEdit(null));
  $("btnDel").addEventListener("click", remove);
  $("btnEdit").addEventListener("click", () => openEdit(profileById(selId)));
  $("btnPrimary").addEventListener("click", primary);
  $("btnSecondary").addEventListener("click", disconnect);
  $("btnCopy").addEventListener("click", () => copyText(propsText(), $("btnCopy")));
  $("user").addEventListener("keydown", (e) => { if (e.key === "Enter") $("pass").focus(); });
  $("pass").addEventListener("keydown", (e) => { if (e.key === "Enter") connect(); });
  $("code").addEventListener("keydown", (e) => { if (e.key === "Enter") submitCode(); });
  $("code").addEventListener("input", () => { $("code").value = $("code").value.replace(/\s+/g, ""); });

  $("eServer").addEventListener("input", () => { cert = null; certView("none"); });
  $("btnCheckCert").addEventListener("click", checkCert);
  $("btnSave").addEventListener("click", save);
  $("btnCancelEdit").addEventListener("click", closeEdit);

  $("btnLogRefresh").addEventListener("click", loadLogs);
  $("btnLogCopy").addEventListener("click", () => copyText(logLines.join("\n"), $("btnLogCopy")));

  $("autostart").addEventListener("change", async (e) => {
    const want = e.target.checked;
    try { await api().SetAutostart(want); } catch (err) { e.target.checked = !want; }
  });
  window.runtime.EventsOn("autostart", (on) => { $("autostart").checked = !!on; });

  $("dlgPrimary").addEventListener("click", () => closeMsg("primary"));
  $("dlgSecondary").addEventListener("click", () => closeMsg("secondary"));
  $("dlgClose").addEventListener("click", () => closeMsg("close"));
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !$("dlg").hidden) closeMsg("close");
    else if (e.key === "Escape" && mode === "edit") closeEdit();
  });

  window.runtime.EventsOn("close-requested", async () => {
    const r = await msgbox({
      title: "FVPN",
      text: "VPN bağlantısı açık. FVPN'den çıksanız da bağlantı açık kalabilir.",
      primary: "Bağlantıyı kes ve çık",
      secondary: "Bağlı kalsın, çık",
    });
    if (r === "primary") api().Quit(true);
    else if (r === "secondary") api().Quit(false);
  });

  window.runtime.EventsOn("focus-login", () => {
    showTab(false);
    if (mode === "edit") return;
    if (!selId && init.profiles.length) { selId = init.profiles[0].id; loadUser(); }
    render();
    if (st() === "need_2fa") $("code").focus();
    else if (!activeId() && selId) ($("user").value ? $("pass") : $("user")).focus();
  });

  window.runtime.EventsOn("status", onStatus);
  setInterval(tick, 1000);
}

window.addEventListener("DOMContentLoaded", () => {
  wire();
  boot().catch((e) => { serviceError = String(e); render(); });
});
