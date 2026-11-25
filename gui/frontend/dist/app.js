"use strict";
// FVPN GUI — NetBird-style main window (toggle) plus a settings view. All
// privileged work happens in the service; this page renders status and
// forwards input via window.go.main.App.

const $ = (id) => document.getElementById(id);
const api = () => window.go.main.App;

let init = { profiles: [], users: {}, lastProfile: "", locked: false };
let status = { state: "idle" };
let serviceError = "";
let selId = null;            // selected profile
let busy = false;
let view = "main";           // main | settings
let tab = "general";
let editing = null;          // profile being edited, null = new
let cert = null;             // CheckCert result
let chalSince = 0;
let loginErrShown = "";      // error already shown in the sign-in dialog
let errSeen = "";            // last service error already presented
let logLines = [];
let loaded = false;          // service data arrived (avoid flashing "No profile")
let opBusy = false;          // 1Password sign-in in progress
let opPhase = "";            // credentials | signin | code | next-code | verify
const OP_LABEL = {
  credentials: "Getting credentials from 1Password...",
  signin: "Signing in...",
  code: "Getting verification code from 1Password...",
  "next-code": "Waiting for the next 1Password code...",
  verify: "Verifying code...",
};
const CHAL_TTL = 180;
const SESSION = ["need_2fa", "connecting", "connected", "disconnecting"];

// ---------- helpers ----------
function cap(s) {
  s = String(s || "").replace(/^Error:\s*/, "");
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}
function show(id, on) { $(id).hidden = !on; }
function text(id, t) { $(id).textContent = t; }
function fieldErr(id, msg) { $(id).textContent = cap(msg); show(id, !!msg); }
function fmtDur(sec) {
  sec = Math.max(0, Math.floor(sec));
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
  return h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${s}s` : `${s}s`;
}
function fmtBytes(n) {
  n = n || 0;
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + " " + u[i];
}
function parseTime(t) {
  if (!t || t.startsWith("0001")) return 0;
  const v = Date.parse(t);
  return isNaN(v) ? 0 : v;
}
function st() { return serviceError ? "idle" : (status.state || "idle"); }
function activeId() { return SESSION.includes(st()) ? status.profile : null; }
function profileById(id) { return init.profiles.find((p) => p.id === id); }
function iconFor(name) {
  return /\b(work|office|company|corp|corporate|business)\b/i.test(name || "") ? "#i-briefcase" : "#i-user-circle";
}
function svgUse(href, cls) {
  const ns = "http://www.w3.org/2000/svg";
  const s = document.createElementNS(ns, "svg");
  s.setAttribute("class", cls);
  const u = document.createElementNS(ns, "use");
  u.setAttribute("href", href);
  s.appendChild(u);
  return s;
}
async function copy(textValue, el) {
  try {
    await navigator.clipboard.writeText(textValue);
    if (el) { el.classList.add("copied"); setTimeout(() => el.classList.remove("copied"), 800); }
    return true;
  } catch (e) { return false; }
}

// ---------- popovers ----------
let openPop = null;
function closePop() {
  if (!openPop) return;
  openPop.pop.hidden = true;
  openPop.anchor.classList.remove("open");
  openPop = null;
}
function togglePop(popId, anchorId, place) {
  const pop = $(popId), anchor = $(anchorId);
  if (openPop && openPop.pop === pop) { closePop(); return; }
  closePop();
  pop.hidden = false;
  anchor.classList.add("open");
  openPop = { pop, anchor };
  const r = anchor.getBoundingClientRect();
  const w = pop.offsetWidth, h = pop.offsetHeight, vw = window.innerWidth;
  let left, top;
  if (place === "top-stretch") {
    pop.style.width = r.width + "px";
    left = r.left; top = r.top - h - 8;
  } else if (place === "bottom-end") {
    left = r.right - w; top = r.bottom + 8;
  } else {
    left = r.left + r.width / 2 - w / 2; top = r.bottom + 8;
  }
  left = Math.max(12, Math.min(left, vw - w - 12));
  pop.style.left = left + "px";
  pop.style.top = Math.max(8, top) + "px";
}

// ---------- dialogs ----------
let dlgOpen = null;
function openDialog(id) {
  for (const d of ["dlgLogin", "dlgCode", "dlgProfile", "dlgMsg"]) show(d, d === id);
  show("overlay", true);
  dlgOpen = id;
}
function closeDialog() {
  show("overlay", false);
  for (const d of ["dlgLogin", "dlgCode", "dlgProfile", "dlgMsg"]) show(d, false);
  dlgOpen = null;
}

let msgResolve = null;
function message({ title, body, primary = "OK", secondary, cancel = false }) {
  text("mTitle", title);
  text("mText", body);
  text("mPrimary", primary);
  text("mSecondary", secondary || "");
  show("mSecondary", !!secondary);
  show("mCancel", cancel);
  openDialog("dlgMsg");
  $("mPrimary").focus();
  return new Promise((r) => { msgResolve = r; });
}
function endMessage(r) {
  closeDialog();
  if (msgResolve) { const f = msgResolve; msgResolve = null; f(r); }
}

// ---------- main view ----------
function renderMain() {
  const s = st();
  const act = activeId();
  const p = profileById(selId);

  // header profile selector
  text("profName", p ? p.name : (loaded ? "No profile" : ""));
  $("profIcon").setAttribute("href", iconFor(p && p.name));
  $("profBtn").disabled = !!act || busy;

  // toggle
  const on = s === "connected" || s === "connecting" || s === "need_2fa" || opBusy;
  const transitioning = s === "connecting" || s === "need_2fa" || s === "disconnecting" || opBusy;
  const tg = $("toggle");
  tg.setAttribute("aria-checked", String(on));
  tg.classList.toggle("pulse", transitioning);
  tg.disabled = !!serviceError || s === "disconnecting" || busy || opBusy;

  let label = "Disconnected";
  if (serviceError) label = "Service unavailable";
  else if (opBusy && s !== "connected") label = OP_LABEL[opPhase] || OP_LABEL.credentials;
  else if (s === "need_2fa") label = "Waiting for verification code";
  else if (s === "connecting") label = "Connecting...";
  else if (s === "connected") label = "Connected";
  else if (s === "disconnecting") label = "Disconnecting...";
  text("statusText", label);

  const up = s === "connected";
  $("lineServer").querySelector("span").textContent = up && p ? p.server : "";
  $("lineIP").querySelector("span").textContent = up ? (status.localIp || "") : "";
  $("lineServer").classList.toggle("show", up && !!p);
  $("lineIP").classList.toggle("show", up && !!status.localIp);
  $("lineServer").tabIndex = up ? 0 : -1;
  $("lineIP").tabIndex = up ? 0 : -1;

  $("detailsBtn").disabled = !up;
  if (!up && openPop && openPop.pop === $("detailsPop")) closePop();
  if (up) {
    text("dUser", status.username || "-");
    text("dRoutes", String(status.routes || 0));
    const dns = status.dnsRules || [];
    $("dDNS").replaceChildren(...dns.map((t) => { const d = document.createElement("div"); d.textContent = t; return d; }));
    if (!dns.length) text("dDNS", "-");
    text("dRx", fmtBytes(status.rxBytes));
    text("dTx", fmtBytes(status.txBytes));
  }
}

function tick() {
  if (st() === "connected") {
    const since = parseTime(status.since);
    text("dFor", since ? fmtDur((Date.now() - since) / 1000) : "-");
    const exp = parseTime(status.expiresAt);
    text("dExp", exp
      ? `${new Date(exp).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })} (in ${fmtDur((exp - Date.now()) / 1000)})`
      : "-");
  }
  if (st() === "need_2fa" && chalSince) {
    const left = CHAL_TTL - (Date.now() - chalSince) / 1000;
    text("codeLeft", left > 0 ? `Expires in ${fmtDur(left)}` : "The code request expired");
  }
}

function renderProfileMenu() {
  const rows = init.profiles.map((p) => {
    const b = document.createElement("button");
    b.className = "pop-item row";
    b.appendChild(svgUse(iconFor(p.name), "ic16"));
    const t = document.createElement("span");
    t.className = "p-text";
    const n = document.createElement("span"); n.className = "p-name"; n.textContent = p.name;
    const sub = document.createElement("span"); sub.className = "p-sub"; sub.textContent = p.server;
    t.append(n, sub);
    b.appendChild(t);
    if (p.id === selId) b.appendChild(svgUse("#i-check", "ic14 p-check"));
    b.addEventListener("click", () => { selectProfile(p.id); closePop(); });
    return b;
  });
  $("profMenuRows").replaceChildren(...rows);
  $("profMenuRows").hidden = rows.length === 0;
  $("profMenu").querySelector(".pop-sep").hidden = rows.length === 0;
}

function selectProfile(id) {
  selId = id;
  render();
}

// ---------- settings view ----------
function setView(v, t) {
  closePop();
  view = v;
  if (t) tab = t;
  api().SetView(v);
  render();
  if (v === "settings" && tab === "logs") loadLogs();
}

function renderSettings() {
  for (const b of document.querySelectorAll(".tab")) {
    const active = b.dataset.tab === tab;
    b.classList.toggle("active", active);
    b.setAttribute("aria-selected", String(active));
  }
  show("tabGeneral", tab === "general");
  show("tabProfiles", tab === "profiles");
  show("tabLogs", tab === "logs");
  show("tabAbout", tab === "about");

  show("lockedNote", init.locked);
  show("addProfileBtn", !init.locked);
  const act = activeId();
  const rows = init.profiles.map((p) => {
    const r = document.createElement("div");
    r.className = "prow";
    r.appendChild(svgUse(iconFor(p.name), "ic16 p-icon"));
    const t = document.createElement("div");
    t.className = "p-text";
    const n = document.createElement("div"); n.className = "p-name";
    const nm = document.createElement("span"); nm.textContent = p.name; n.appendChild(nm);
    if (p.id === act) { const tag = document.createElement("span"); tag.className = "p-tag"; tag.textContent = "In use"; n.appendChild(tag); }
    const sub = document.createElement("div"); sub.className = "p-sub selectable";
    sub.textContent = p.server + (p.realm ? ` · realm ${p.realm}` : "") + (p.trustedCert ? " · pinned certificate" : "") + (opActive(p.id) ? " · 1Password" : "");
    t.append(n, sub);
    r.appendChild(t);
    if (!init.locked) {
      const a = document.createElement("div"); a.className = "p-act";
      const ed = document.createElement("button"); ed.className = "act-btn"; ed.title = "Edit"; ed.setAttribute("aria-label", "Edit " + p.name);
      ed.appendChild(svgUse("#i-pencil", "ic16")); ed.disabled = p.id === act;
      ed.addEventListener("click", () => openProfileDialog(p));
      const del = document.createElement("button"); del.className = "act-btn danger"; del.title = "Delete"; del.setAttribute("aria-label", "Delete " + p.name);
      del.appendChild(svgUse("#i-trash", "ic16")); del.disabled = p.id === act;
      del.addEventListener("click", () => deleteProfile(p));
      a.append(ed, del);
      r.appendChild(a);
    }
    return r;
  });
  $("profileRows").replaceChildren(...rows);
  show("profilesEmpty", rows.length === 0);
}

// ---------- render ----------
function render() {
  show("vMain", view === "main");
  show("vSettings", view === "settings");
  renderMain();
  renderSettings();
  renderProfileMenu();
  tick();
}

function onStatus(ev) {
  applyStatus(ev.status, ev.serviceError || "");
}

// applyStatus is the single entry point for every status change (poll events
// and action responses), so transitions are never missed.
function applyStatus(next, svcErr) {
  const prev = st();
  if (svcErr !== undefined) serviceError = svcErr;
  if (next) status = next;
  const s = st();

  if (s === "need_2fa" && prev !== "need_2fa") {
    chalSince = Date.now();
    $("code").value = "";
    fieldErr("codeErr", "");
    if (status.profile) selId = status.profile;
  }
  // Waiting for the second factor: the code dialog must be visible whenever
  // nothing else is on screen (also recovers if it was closed somehow).
  if (s === "need_2fa" && !opBusy && dlgOpen !== "dlgCode" && dlgOpen !== "dlgMsg") openCode();
  if (s !== "need_2fa") {
    chalSince = 0;
    if (dlgOpen === "dlgCode") closeDialog();
  }
  // a new error from the service (not already shown inline)
  if (s === "error" && !opBusy && status.lastError && status.lastError !== errSeen) {
    errSeen = status.lastError;
    const msg = cap(status.lastError);
    if (msg !== loginErrShown && dlgOpen !== "dlgLogin") {
      message({ title: prev === "connected" ? "Connection lost" : "Connection failed", body: msg });
    }
  }
  if (s !== "error") errSeen = "";
  render();
}

async function guarded(fn) {
  if (busy) return;
  busy = true;
  render();
  try { const s = await fn(); if (s) applyStatus(s); } finally { busy = false; render(); }
}

function openCode() {
  if (view !== "main") setView("main");
  text("codeDesc", cap(status.message || "Enter the verification code"));
  openDialog("dlgCode");
  setTimeout(() => $("code").focus(), 0);
}

// ---------- connect flow ----------
function onToggle() {
  const s = st();
  if (s === "need_2fa") { openCode(); return; }   // cancel lives in the dialog
  if (s === "connected" || s === "connecting") { disconnect(); return; }
  if (!selId) { setView("settings", "profiles"); openProfileDialog(null); return; }
  if (opActive(selId)) { autoConnect(); return; }
  openLogin();
}

function opFor(id) { return (init.onePassword && init.onePassword[id]) || { enabled: false, item: "", vault: "", account: "" }; }
function opActive(id) { return !!init.onePasswordOn && opFor(id).enabled; }

// Sign in with 1Password: credentials (and the one-time code, unless the user
// enters it) are fetched and submitted by the Go side; nothing secret passes
// through this page.
async function autoConnect() {
  if (opBusy) return;
  const id = selId;
  opBusy = true;
  opPhase = "credentials";
  render();
  try {
    const s = await api().ConnectWith1Password(id);
    if (s) applyStatus(s);
  } catch (e) {
    const msg = cap(String(e));
    opBusy = false;
    if (msg.startsWith("1Password:")) {
      if (st() === "need_2fa") { openCode(); fieldErr("codeErr", msg); }
      else { openLogin(); fieldErr("loginErr", msg); }
    } else {
      loginErrShown = msg;   // the status poll would report the same error
      errSeen = status.lastError || "";
      message({ title: "Connection failed", body: msg });
    }
  } finally {
    opBusy = false;
    opPhase = "";
    render();
    // Manual code (or a challenge left open): ask for it right away.
    if (st() === "need_2fa" && dlgOpen !== "dlgCode" && dlgOpen !== "dlgMsg") openCode();
  }
}

function openLogin() {
  const p = profileById(selId);
  if (!p) return;
  text("loginDesc", `${p.name} · ${p.server}`);
  $("user").value = init.users[p.id] || "";
  $("pass").value = "";
  $("pass").classList.remove("err");
  fieldErr("loginErr", "");
  loginErrShown = "";
  openDialog("dlgLogin");
  ($("user").value ? $("pass") : $("user")).focus();
}

function submitLogin() {
  const user = $("user").value.trim();
  const pass = $("pass").value;
  if (!user) { $("user").focus(); return; }
  if (!pass) { $("pass").focus(); return; }
  const id = selId;
  $("loginGo").disabled = true;
  guarded(async () => {
    try {
      const s = await api().Connect(id, user, pass);
      init.users[id] = user;
      init.lastProfile = id;
      if (dlgOpen === "dlgLogin") closeDialog();
      return s;
    } catch (e) {
      loginErrShown = cap(String(e));
      $("pass").classList.add("err");
      fieldErr("loginErr", loginErrShown);
      $("pass").focus();
    } finally {
      $("pass").value = "";
      $("loginGo").disabled = false;
    }
  });
}

function submitCode() {
  const code = $("code").value.trim();
  if (!code) { $("code").focus(); return; }
  $("codeGo").disabled = true;
  guarded(async () => {
    try {
      return await api().Submit2FA(code);
    } catch (e) {
      // the session is gone; onStatus shows the error dialog
    } finally {
      $("code").value = "";
      $("codeGo").disabled = false;
    }
  });
}

function disconnect() {
  guarded(() => api().Disconnect().catch(() => null));
}

// ---------- profiles ----------
function openProfileDialog(p) {
  editing = p || null;
  cert = null;
  text("pTitle", p ? "Edit profile" : "Add profile");
  $("pName").value = p ? p.name : "";
  $("pServer").value = p ? p.server : "";
  $("pRealm").value = p ? (p.realm || "") : "";
  $("pPin").checked = false;
  certView("none");
  fieldErr("pErr", "");
  const op = p ? opFor(p.id) : opFor("");
  setOpUI(op.enabled);
  $("opItem").value = op.item || "";
  $("opVault").value = op.vault || "";
  $("opAccount").value = op.account || "";
  $("opOtpItem").value = op.otpItem || "";
  $("opOtpVault").value = op.otpVault || "";
  $("opOtpAccount").value = op.otpAccount || "";
  setOtpUI(op.manualOtp ? "manual" : (op.otpItem || op.otpVault || op.otpAccount) ? "separate" : "item");
  show("opSection", !!init.onePasswordOn);
  text("opState", "");
  openDialog("dlgProfile");
  $("pName").focus();
}

function certView(mode) {
  const same = editing && $("pServer").value.trim() === editing.server;
  show("certBox", mode === "checked");
  show("pinRow", mode === "checked" && !cert.verified);
  $("certCheck").disabled = mode === "checking";
  const s = $("certState");
  if (mode === "checking") { s.textContent = "Checking..."; return; }
  if (mode === "checked") {
    s.textContent = cert.verified ? "Trusted by Windows" : "Not trusted by Windows";
    text("cSubject", cert.subject);
    text("cIssuer", cert.issuer);
    text("cExpiry", cert.notAfter);
    text("cFp", cert.fingerprint);
    return;
  }
  if (same && editing.trustedCert) s.textContent = "Pinned (" + editing.trustedCert.slice(0, 12) + "…)";
  else if (same) s.textContent = "Verified by Windows";
  else s.textContent = "Not checked";
}

async function checkCert() {
  const server = $("pServer").value.trim();
  if (!server) { fieldErr("pErr", "Enter the server address"); return; }
  fieldErr("pErr", "");
  certView("checking");
  try {
    cert = await api().CheckCert(server);
    $("pServer").value = cert.server;
    $("pPin").checked = false;
    certView("checked");
  } catch (e) {
    cert = null;
    certView("none");
    fieldErr("pErr", String(e));
  }
}

async function saveProfile() {
  const name = $("pName").value.trim();
  const server = $("pServer").value.trim();
  if (!name) { fieldErr("pErr", "Enter a profile name"); return; }
  if (!server) { fieldErr("pErr", "Enter the server address"); return; }
  const op = opForm();
  if (init.onePasswordOn && op.enabled && !op.item) { fieldErr("pErr", "Enter the 1Password item"); $("opItem").focus(); return; }
  if (init.onePasswordOn && op.enabled && otpMode() === "separate" && !op.otpItem) { fieldErr("pErr", "Enter the 1Password item for the one-time password"); $("opOtpItem").focus(); return; }
  let pin = "";
  const same = editing && server === editing.server;
  if (cert) {
    if (!cert.verified) {
      if (!$("pPin").checked) { fieldErr("pErr", "The certificate is not trusted. Tick \"Trust this certificate\" to save."); return; }
      pin = cert.fingerprint;
    }
  } else if (same) {
    pin = editing.trustedCert || "";
  } else {
    fieldErr("pErr", "Check the server certificate first.");
    return;
  }
  $("pSave").disabled = true;
  fieldErr("pErr", "");
  try {
    const id = await api().SaveProfile({
      id: editing ? editing.id : "",
      name,
      server: cert ? cert.server : server,
      realm: $("pRealm").value.trim(),
      trustedCert: pin,
    });
    if (init.onePasswordOn) {
      await api().Set1Password(id, op);
      init.onePassword = init.onePassword || {};
      init.onePassword[id] = op;
    }
    await reloadProfiles();
    if (!editing || !selId) selId = id;
    closeDialog();
    render();
  } catch (e) {
    fieldErr("pErr", String(e));
  } finally {
    $("pSave").disabled = false;
  }
}

function setOpUI(on) {
  $("opEnabled").setAttribute("aria-checked", String(!!on));
  show("opFields", !!on);
}

function otpMode() {
  const r = document.querySelector('input[name="opOtpMode"]:checked');
  return r ? r.value : "item";
}

function setOtpUI(mode) {
  for (const r of document.querySelectorAll('input[name="opOtpMode"]')) r.checked = r.value === mode;
  show("opOtpFields", mode === "separate");
}

function opForm() {
  const mode = otpMode(), sep = mode === "separate";
  return {
    enabled: $("opEnabled").getAttribute("aria-checked") === "true",
    item: $("opItem").value.trim(),
    vault: $("opVault").value.trim(),
    account: $("opAccount").value.trim(),
    otpItem: sep ? $("opOtpItem").value.trim() : "",
    otpVault: sep ? $("opOtpVault").value.trim() : "",
    otpAccount: sep ? $("opOtpAccount").value.trim() : "",
    manualOtp: mode === "manual",
  };
}

async function testOP() {
  const op = opForm();
  if (!op.item) { $("opItem").focus(); return; }
  if (otpMode() === "separate" && !op.otpItem) { $("opOtpItem").focus(); return; }
  const s = $("opState");
  s.classList.remove("op-ok");
  s.textContent = "Waiting for 1Password...";
  $("opTest").disabled = true;
  try {
    const r = await api().Test1Password(op);
    const otp = r.manualOtp ? "code entered manually"
      : r.hasOtp ? (r.separateOtp ? "one-time password found in the other item" : "one-time password found")
      : (r.separateOtp ? "no one-time password in the other item" : "no one-time password");
    const parts = [r.username || "no username", r.hasPassword ? "password found" : "no password", otp];
    s.textContent = parts.join(" · ");
    s.classList.add("op-ok");
  } catch (e) {
    s.textContent = cap(String(e));
  } finally {
    $("opTest").disabled = false;
  }
}

async function deleteProfile(p) {
  const r = await message({
    title: "Delete profile?",
    body: `"${p.name}" will be removed from this computer.`,
    primary: "Delete",
    cancel: true,
  });
  if (r !== "primary") return;
  try {
    await api().DeleteProfile(p.id);
    await reloadProfiles();
    if (selId === p.id) selId = init.profiles.length ? init.profiles[0].id : null;
  } catch (e) {
    await message({ title: "Could not delete profile", body: cap(String(e)) });
  }
  render();
}

async function reloadProfiles() {
  const r = await api().Profiles();
  init.profiles = r.profiles || [];
  init.locked = !!r.locked;
}

// ---------- logs ----------
async function loadLogs() {
  try { logLines = (await api().Logs()) || []; } catch (e) { logLines = [cap(String(e))]; }
  text("logText", logLines.join("\n") || "No entries.");
  const el = $("logText");
  el.scrollTop = el.scrollHeight;
}

// ---------- boot ----------
function setAutostartUI(on) { $("autostart").setAttribute("aria-checked", String(!!on)); }

async function setOpOnUI(on) {
  $("opOn").setAttribute("aria-checked", String(!!on));
  const el = $("opToolState");
  if (!on) { show("opToolState", false); return; }
  let t = null;
  try { t = await api().OnePasswordTool(); } catch (e) { t = { found: false, error: String(e) }; }
  if ($("opOn").getAttribute("aria-checked") !== "true") return;   // switched off meanwhile
  el.textContent = t.found ? "" : cap(t.error || "1Password CLI not found");
  show("opToolState", !t.found);
}

function markT(name) { try { api().Mark(name); } catch (e) { /* timing only */ } }

async function boot() {
  // Draw immediately; profile data from the service fills in when it arrives.
  render();
  markT("first render");
  init = await api().Init();
  loaded = true;
  markT("service answered (Init)");
  init.profiles = init.profiles || [];
  init.users = init.users || {};
  text("aboutVersion", "Version " + init.version);
  setAutostartUI(await api().GetAutostart());
  init.onePasswordOn = !!init.onePasswordOn;
  setOpOnUI(init.onePasswordOn);
  selId = init.profiles.some((p) => p.id === init.lastProfile) ? init.lastProfile : (init.profiles[0] || {}).id || null;
  if (init.error) serviceError = init.error;
  render();
  markT("ready");
}

function wire() {
  $("toggle").addEventListener("click", onToggle);
  $("profBtn").addEventListener("click", () => togglePop("profMenu", "profBtn", "bottom-center"));
  $("menuBtn").addEventListener("click", () => togglePop("mainMenu", "menuBtn", "bottom-end"));
  $("detailsBtn").addEventListener("click", () => togglePop("detailsPop", "detailsBtn", "top-stretch"));
  $("manageProfiles").addEventListener("click", () => setView("settings", "profiles"));
  $("menuSettings").addEventListener("click", () => setView("settings", "general"));
  $("menuLogs").addEventListener("click", () => setView("settings", "logs"));
  $("lineServer").addEventListener("click", (e) => copy($("lineServer").querySelector("span").textContent, e.currentTarget));
  $("lineIP").addEventListener("click", (e) => copy($("lineIP").querySelector("span").textContent, e.currentTarget));

  $("backBtn").addEventListener("click", () => setView("main"));
  for (const b of document.querySelectorAll(".tab")) {
    b.addEventListener("click", () => { tab = b.dataset.tab; render(); if (tab === "logs") loadLogs(); });
  }
  $("autostart").addEventListener("click", async () => {
    const want = $("autostart").getAttribute("aria-checked") !== "true";
    setAutostartUI(want);
    try { await api().SetAutostart(want); } catch (e) { setAutostartUI(!want); }
  });
  $("opOn").addEventListener("click", async () => {
    const want = $("opOn").getAttribute("aria-checked") !== "true";
    try { await api().Set1PasswordOn(want); } catch (e) { return; }
    init.onePasswordOn = want;
    setOpOnUI(want);
    render();
  });
  $("addProfileBtn").addEventListener("click", () => openProfileDialog(null));
  $("logRefresh").addEventListener("click", loadLogs);
  $("logCopy").addEventListener("click", (e) => copy(logLines.join("\n"), e.currentTarget));

  // dialogs
  for (const b of document.querySelectorAll("[data-close]")) b.addEventListener("click", closeDialog);
  $("loginGo").addEventListener("click", submitLogin);
  $("user").addEventListener("keydown", (e) => { if (e.key === "Enter") $("pass").focus(); });
  $("pass").addEventListener("keydown", (e) => { if (e.key === "Enter") submitLogin(); });
  $("pass").addEventListener("input", () => $("pass").classList.remove("err"));
  $("codeGo").addEventListener("click", submitCode);
  $("code").addEventListener("keydown", (e) => { if (e.key === "Enter") submitCode(); });
  $("code").addEventListener("input", () => { $("code").value = $("code").value.replace(/\s+/g, ""); });
  $("codeCancel").addEventListener("click", () => { closeDialog(); disconnect(); });
  $("codeX").addEventListener("click", () => { closeDialog(); disconnect(); });
  $("pServer").addEventListener("input", () => { cert = null; certView("none"); });
  $("certCheck").addEventListener("click", checkCert);
  $("opEnabled").addEventListener("click", () => setOpUI($("opEnabled").getAttribute("aria-checked") !== "true"));
  for (const r of document.querySelectorAll('input[name="opOtpMode"]')) r.addEventListener("change", () => setOtpUI(otpMode()));
  $("opTest").addEventListener("click", testOP);
  $("pSave").addEventListener("click", saveProfile);
  $("mPrimary").addEventListener("click", () => endMessage("primary"));
  $("mSecondary").addEventListener("click", () => endMessage("secondary"));
  $("mCancel").addEventListener("click", () => endMessage("cancel"));
  $("mX").addEventListener("click", () => endMessage("cancel"));

  document.addEventListener("mousedown", (e) => {
    if (openPop && !openPop.pop.contains(e.target) && !openPop.anchor.contains(e.target)) closePop();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (openPop) { closePop(); return; }
      if (dlgOpen === "dlgMsg") { endMessage("cancel"); return; }
      if (dlgOpen === "dlgCode") return;          // explicit Cancel only
      if (dlgOpen) { closeDialog(); return; }
      if (view === "settings") setView("main");
    }
    if (e.key === "," && e.ctrlKey) { e.preventDefault(); setView("settings", "general"); }
  });

  window.runtime.EventsOn("autostart", setAutostartUI);
  window.runtime.EventsOn("close-requested", async () => {
    const r = await message({
      title: "Quit FVPN?",
      body: "The VPN is connected. It can stay connected after FVPN quits.",
      primary: "Disconnect and quit",
      secondary: "Quit and stay connected",
      cancel: true,
    });
    if (r === "primary") api().Quit(true);
    else if (r === "secondary") api().Quit(false);
  });
  window.runtime.EventsOn("focus-login", () => {
    if (view !== "main") setView("main");
    const s = st();
    if (s === "need_2fa") { openCode(); return; }
    if (!activeId() && !dlgOpen) onToggle();
  });
  window.runtime.EventsOn("op-phase", (p) => { opPhase = p; render(); });
  window.runtime.EventsOn("status", onStatus);
  setInterval(tick, 1000);
}

window.addEventListener("DOMContentLoaded", () => {
  markT("DOMContentLoaded");
  wire();
  boot().catch((e) => { serviceError = String(e); render(); });
});
