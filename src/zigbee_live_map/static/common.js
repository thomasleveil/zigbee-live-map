/* Shared by every page: preferences, translations, theme, and the settings dialog.
   Texts live in locales/<code>.json. English is the reference and the fallback for any missing key. */
"use strict";
const ZLM = (() => {
  const prefs = {
    get(key, fallback) { try { return localStorage.getItem("zlm-" + key) ?? fallback; } catch (_) { return fallback; } },
    set(key, value) { try { value == null ? localStorage.removeItem("zlm-" + key) : localStorage.setItem("zlm-" + key, value); } catch (_) {} },
  };
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  // Translators can mark **bold** and *italic*; nothing else in a translation is ever treated as HTML.
  const rich = s => esc(s).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/\*(.+?)\*/g, "<i>$1</i>");
  const emit = name => document.dispatchEvent(new CustomEvent(name));
  // Signed out (the tool was restarted, or the session ended): on a network the password is asked for again. Never from the login page itself.
  function signedOut(response) {
    if (response.status !== 401) return false;
    if (!/\/login$/.test(location.pathname)) location.assign("login");
    return true;
  }
  // Changes and the live connection need the session token, which only a page of this tool can read.
  // Every URL here is relative, so the pages work at "/" and under any path prefix a reverse proxy adds.
  let tokenPromise = null, canSignOut = false;
  function token(fresh) {
    if (fresh || !tokenPromise) tokenPromise = fetch("api/session", { cache: "no-store" }).then(r => signedOut(r) ? {} : r.json()).then(d => { canSignOut = !!d.signOut; return d.token || ""; }).catch(() => { tokenPromise = null; return ""; });
    return tokenPromise;
  }
  async function getJson(url, options = {}) {
    const changing = options.method && options.method !== "GET";
    const send = async fresh => fetch(url, { cache: "no-store", ...options, headers: { ...options.headers, ...(changing ? { "X-ZLM-Token": await token(fresh) } : {}) } });
    let response = await send(false);
    if (response.status === 403 && changing) response = await send(true);   // the tool was restarted: its token changed
    const data = await response.json().catch(() => ({}));
    if (signedOut(response)) throw new Error(data.error || "401");
    if (!response.ok) throw new Error(data.error || `${response.status}`);
    return data;
  }

  // ---- translations
  let locales = [{ code: "en", name: "English" }], reference = {}, strings = {}, lang = "en";
  const has = key => key in strings || key in reference;
  function t(key, vars) {
    const text = strings[key] ?? reference[key];
    if (text === undefined) return key;
    return vars ? text.replace(/\{(\w+)\}/g, (m, name) => (name in vars ? vars[name] : m)) : text;
  }
  function resolveLang(pref) {
    if (pref !== "auto" && locales.some(l => l.code === pref)) return pref;
    const wanted = navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language || "en"];
    for (const want of wanted) {
      const low = want.toLowerCase(), base = low.split("-")[0];
      const hit = locales.find(l => l.code.toLowerCase() === low) || locales.find(l => l.code.toLowerCase().split("-")[0] === base);
      if (hit) return hit.code;
    }
    return "en";
  }
  function translate(root) {
    for (const el of root.querySelectorAll("[data-i18n]")) el.textContent = t(el.dataset.i18n);
    for (const el of root.querySelectorAll("[data-i18n-aria]")) el.setAttribute("aria-label", t(el.dataset.i18nAria));
    for (const el of root.querySelectorAll("[data-i18n-placeholder]")) el.placeholder = t(el.dataset.i18nPlaceholder);
    for (const el of root.querySelectorAll("[data-i18n-title]")) el.title = t(el.dataset.i18nTitle);
  }
  async function applyLang() {
    lang = resolveLang(prefs.get("lang", "auto"));
    strings = lang === "en" ? reference : await getJson(`locales/${lang}.json`).catch(() => reference);
    document.documentElement.lang = lang;
    translate(document);
    emit("zlm:lang");
  }
  async function setLang(pref) { prefs.set("lang", pref === "auto" ? null : pref); await applyLang(); }

  // ---- theme: light, dark, or whatever the system says
  const systemDark = matchMedia("(prefers-color-scheme: dark)");
  function applyTheme() {
    const pref = prefs.get("theme", "auto");
    document.documentElement.dataset.theme = pref === "light" || pref === "dark" ? pref : (systemDark.matches ? "dark" : "light");
    emit("zlm:theme");
  }
  function setTheme(pref) { prefs.set("theme", pref === "auto" ? null : pref); applyTheme(); }
  systemDark.addEventListener("change", applyTheme);
  applyTheme();

  // ---- settings dialog
  let dialog = null, extras = null;
  function buildSettings() {
    dialog = document.createElement("dialog");
    dialog.className = "settings"; dialog.setAttribute("aria-labelledby", "zlmSetTitle");
    dialog.innerHTML = `
      <header><h2 id="zlmSetTitle" data-i18n="settings.title"></h2><button type="button" id="zlmSetClose" data-i18n-aria="settings.close">×</button></header>
      <div class="body">
        <section><label class="lead" for="zlmLang" data-i18n="settings.language"></label><select id="zlmLang"></select><p class="note" data-i18n="settings.translate"></p></section>
        <section role="radiogroup" aria-labelledby="zlmThemeTitle"><h3 id="zlmThemeTitle" data-i18n="settings.theme"></h3><div class="row" id="zlmTheme"></div></section>
        <section id="zlmExtras" hidden></section>
        <section><h3 data-i18n="keys.title"></h3><p class="note" data-i18n="keys.help"></p>
          <div class="keylist" id="zlmKeyList"></div>
          <form class="keyform" id="zlmKeyForm">
            <label class="wide"><span data-i18n="keys.key"></span><input id="zlmKeyVal" type="text" autocomplete="off" spellcheck="false" placeholder="aabbcc… (32)" maxlength="47"></label>
            <label><span data-i18n="keys.pan"></span><input id="zlmKeyPan" type="text" autocomplete="off" spellcheck="false" placeholder="0x1a62" maxlength="6"></label>
            <label><span data-i18n="keys.label"></span><input id="zlmKeyLabel" type="text" autocomplete="off" maxlength="60"></label>
            <button type="submit" data-i18n="keys.add"></button>
          </form>
          <p class="note" id="zlmKeyMsg" role="status"></p></section>
        <section aria-labelledby="zlmHueTitle"><h3 id="zlmHueTitle" data-i18n="hue.title"></h3><p class="note" data-i18n="hue.help"></p>
          <p id="zlmHueStatus" role="status"></p>
          <div id="zlmHueSetup">
            <p><button type="button" id="zlmHueFind" data-i18n="hue.find"></button></p>
            <ul class="huefound" id="zlmHueFound"></ul>
            <form class="hueform" id="zlmHuePair">
              <label class="wide"><span data-i18n="hue.host"></span><input id="zlmHueHost" type="text" autocomplete="off" spellcheck="false" maxlength="255" placeholder="10.0.0.5"></label>
              <button type="submit" data-i18n="hue.pair"></button>
            </form>
            <p class="note" data-i18n="hue.pair.help"></p>
            <form class="hueform" id="zlmHueKeyForm">
              <label class="wide"><span data-i18n="hue.key"></span><input id="zlmHueKey" type="password" autocomplete="off" spellcheck="false" maxlength="128"></label>
              <button type="submit" data-i18n="hue.key.use"></button>
            </form>
            <p class="note" data-i18n="hue.trust"></p>
          </div>
          <p id="zlmHueManage" class="row"><button type="button" id="zlmHueRefresh" data-i18n="hue.refresh"></button><button type="button" id="zlmHueForget"></button></p>
          <p class="note" id="zlmHueMsg" role="status"></p></section>
        <section><h3 data-i18n="settings.vendors"></h3><p id="zlmVendorStatus" role="status"></p>
          <p><button type="button" id="zlmVendorRefresh" data-i18n="settings.vendors.refresh"></button></p><p class="note" data-i18n="settings.vendors.help"></p></section>
        <section id="zlmSignOut" hidden><p class="note" data-i18n="login.signout.help"></p><p><button type="button" id="zlmSignOutBtn" data-i18n="login.signout"></button></p></section>
        <section><h3 data-i18n="settings.devices"></h3><p class="note" data-i18n="settings.devices.help"></p><p><a class="btn" href="devices" data-i18n="settings.devices.open"></a></p></section>
      </div>`;
    document.body.appendChild(dialog);
    const q = id => dialog.querySelector("#" + id);
    q("zlmSetClose").addEventListener("click", () => dialog.close());
    dialog.addEventListener("click", ev => { if (ev.target === dialog) dialog.close(); });
    q("zlmLang").addEventListener("change", ev => setLang(ev.target.value));
    q("zlmTheme").innerHTML = ["auto", "light", "dark"].map(v => `<label class="opt"><input type="radio" name="zlmTheme" value="${v}"><span data-i18n="settings.theme.${v}"></span></label>`).join("");
    q("zlmTheme").addEventListener("change", ev => setTheme(ev.target.value));
    q("zlmVendorRefresh").addEventListener("click", async () => {
      const button = q("zlmVendorRefresh"), status = q("zlmVendorStatus");
      button.disabled = true; status.textContent = t("settings.vendors.refreshing");
      try { showVendors(await getJson("api/vendors/refresh", { method: "POST" }), t("settings.vendors.done") + " "); }
      catch (err) { status.textContent = t("settings.vendors.failed", { error: err.message }); }
      button.disabled = false;
    });
    q("zlmKeyForm").addEventListener("submit", async ev => {
      ev.preventDefault();
      const pan = q("zlmKeyPan").value.trim(), key = q("zlmKeyVal").value.trim(), label = q("zlmKeyLabel").value.trim();
      try {
        const res = await getJson(`api/keys/${encodeURIComponent(pan)}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ key, label }) });
        renderKeys(res.keys, res.pan); q("zlmKeyVal").value = ""; q("zlmKeyLabel").value = ""; q("zlmKeyMsg").textContent = t("keys.saved");
      } catch (err) { q("zlmKeyMsg").textContent = t("keys.failed", { error: err.message }); }
    });
    dialog.addEventListener("close", () => clearTimeout(hueTimer));
    q("zlmHueFind").addEventListener("click", async () => {
      const button = q("zlmHueFind"), msg = q("zlmHueMsg");
      button.disabled = true; msg.textContent = t("hue.finding");
      try { hueFound = (await getJson("api/hue/discover", { method: "POST" })).bridges; renderFound(); msg.textContent = hueFound.length ? "" : t("hue.found.none"); }
      catch (err) { msg.textContent = t("hue.failed", { error: err.message }); }
      button.disabled = false;
    });
    q("zlmHuePair").addEventListener("submit", ev => { ev.preventDefault(); hueCall("api/hue/pair", "POST", { host: q("zlmHueHost").value }); });
    q("zlmHueKeyForm").addEventListener("submit", async ev => {
      ev.preventDefault();
      if (await hueCall("api/hue/key", "POST", { host: q("zlmHueHost").value, key: q("zlmHueKey").value })) q("zlmHueKey").value = "";
    });
    q("zlmSignOutBtn").addEventListener("click", async () => { try { await getJson("logout", { method: "POST" }); } catch (_) {} location.assign("login"); });
    q("zlmHueRefresh").addEventListener("click", () => hueCall("api/hue/refresh", "POST"));
    q("zlmHueForget").addEventListener("click", () => hueCall("api/hue", "DELETE"));
    if (extras) { q("zlmExtras").hidden = false; extras(q("zlmExtras")); }
  }
  // ---- Hue Bridge: the page only ever learns whether a bridge is set up, its name and id, when it was read, and the last error
  let hue = null, hueFound = null, hueTimer = null;
  function renderFound() {
    const box = dialog.querySelector("#zlmHueFound");
    box.innerHTML = (hueFound || []).map((b, i) => `<li><span>${esc(t("hue.found.row", { name: b.name, id: b.bridgeId || "?", host: b.host }))}</span> <button type="button" data-i="${i}">${esc(t("hue.found.use", { name: b.name }))}</button></li>`).join("");
    for (const b of box.querySelectorAll("button")) b.addEventListener("click", () => { const input = dialog.querySelector("#zlmHueHost"); input.value = hueFound[b.dataset.i].host; input.focus(); });
  }
  function renderHue(st) {
    if (st) hue = st;
    if (!dialog || !hue) return;
    const q = id => dialog.querySelector("#" + id), waiting = hue.pairing === "waiting";
    let text;
    if (waiting) text = t("hue.waiting");
    else if (hue.configured) text = t(hue.lastRead ? "hue.status.ok" : "hue.status.never", { name: hue.name, id: hue.bridgeId, time: hue.lastRead ? new Date(hue.lastRead * 1000).toLocaleTimeString(lang) : "" });
    else text = t(hue.pairing === "timeout" ? "hue.timeout" : "hue.none");
    if (hue.configured && hue.channel) text += " " + t("hue.status.channel", { channel: hue.channel });
    if (hue.error) text += " " + t("hue.status.error", { error: hue.error });
    q("zlmHueStatus").textContent = text;
    q("zlmHueSetup").hidden = hue.configured || waiting;
    q("zlmHueManage").hidden = !hue.configured && !waiting;
    q("zlmHueRefresh").hidden = waiting;
    q("zlmHueForget").textContent = t(waiting ? "hue.cancel" : "hue.forget");
    clearTimeout(hueTimer);
    if (waiting && dialog.open) hueTimer = setTimeout(pollHue, 1000);   // pairing runs on the server: ask how it is going
  }
  async function pollHue() { try { renderHue(await getJson("api/hue")); } catch (_) { hueTimer = setTimeout(pollHue, 2000); } }
  async function hueCall(url, method, body) {
    const msg = dialog.querySelector("#zlmHueMsg");
    msg.textContent = "";
    try { renderHue(await getJson(url, { method, headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined })); return true; }
    catch (err) { msg.textContent = t("hue.failed", { error: err.message }); return false; }
  }
  function renderKeys(list, currentPan) {
    const box = dialog.querySelector("#zlmKeyList"), panInput = dialog.querySelector("#zlmKeyPan");
    if (currentPan && !panInput.value) panInput.value = currentPan;
    if (!list || !list.length) { box.innerHTML = `<p class="note">${esc(t("keys.none"))}</p>`; return; }
    box.innerHTML = list.map(k => `<div class="krow"><span class="kpan">${esc(k.pan)}</span><span class="klabel">${esc(k.label || "")}</span><button type="button" data-pan="${esc(k.pan)}" data-i18n="keys.remove"></button><span class="kval">${esc(k.key)}</span></div>`).join("");
    translate(box);
    for (const b of box.querySelectorAll("button[data-pan]")) b.addEventListener("click", async () => {
      try { const res = await getJson(`api/keys/${encodeURIComponent(b.dataset.pan)}`, { method: "DELETE" }); renderKeys(res.keys, res.pan); } catch (_) {}
    });
  }
  function showVendors(meta, prefix = "") {
    dialog.querySelector("#zlmVendorStatus").textContent = prefix + t("settings.vendors.status", { entries: meta.entries, date: meta.date || "?", origin: t("settings.vendors.origin." + meta.origin) });
  }
  function fillSettings() {
    const select = dialog.querySelector("#zlmLang");
    select.innerHTML = `<option value="auto">${esc(t("settings.language.auto"))}</option>` + locales.map(l => `<option value="${esc(l.code)}">${esc(l.name)}</option>`).join("");
    select.value = prefs.get("lang", "auto");
    const theme = prefs.get("theme", "auto");
    for (const radio of dialog.querySelectorAll('input[name="zlmTheme"]')) radio.checked = radio.value === theme;
    translate(dialog); renderFound(); renderHue();
  }
  async function openSettings() {
    if (!dialog) buildSettings();
    fillSettings(); dialog.showModal();
    token().then(() => { dialog.querySelector("#zlmSignOut").hidden = !canSignOut; });   // only a password-protected server has a session to end
    try { const d = await getJson("api/keys"); renderKeys(d.keys, d.pan); } catch (_) {}
    try { showVendors(await getJson("api/vendors")); } catch (_) {}
    try { renderHue(await getJson("api/hue")); } catch (_) {}
  }
  document.addEventListener("zlm:lang", () => { if (dialog) fillSettings(); });

  async function init() {
    try { locales = await getJson("locales"); reference = await getJson("locales/en.json"); } catch (_) {}
    strings = reference;
    await applyLang();
  }
  return { init, t, has, esc, rich, translate, prefs, getJson, token, openSettings, hueChanged: renderHue, setExtras(fn) { extras = fn; }, get lang() { return lang; } };
})();
