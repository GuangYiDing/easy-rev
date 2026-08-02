/**
 * Easy-Rev Chrome extension — full RE parity with Camoufox path:
 * chrome.debugger Network + inject page_hooks.js (fetch/XHR/crypto) + dump + oracle probe
 * → POST to local bridge → capture JSON with auto_sign / dependency_graph.
 *
 * Capture modes:
 * 1) analyze — fixed listen window (legacy)
 * 2) record  — start once, user operates freely, idle/max auto-upload or manual stop
 *
 * v0.3 UX:
 * - in-page HUD, desktop notifications
 * - re-inject hooks on navigation
 * - persist session so MV3 SW restart can resume
 * - cancel without upload
 */

const DEFAULT_BRIDGE = "http://127.0.0.1:18766";
const SESSION_STORE_KEY = "activeRecordSessions";
const MAX_PERSIST_EVENTS = 800;

/** @type {Map<number, object>} tabId -> live oracle sessions */
const liveSessions = new Map();

/** @type {Map<number, object>} tabId -> active recording session */
const recordSessions = new Map();

/** avoid double-binding after SW restart */
let debuggerEventBound = false;
let resumeAttempted = false;

// ---------- messaging ----------

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || !msg.type) return;
  if (msg.type === "ping") {
    sendResponse({ ok: true, version: "0.3.0" });
    return;
  }
  if (msg.type === "analyze") {
    runAnalyze(msg)
      .then((r) => sendResponse(r))
      .catch((e) =>
        sendResponse({ ok: false, error: String(e && e.message ? e.message : e) })
      );
    return true;
  }
  if (msg.type === "record_start") {
    recordStart(msg)
      .then((r) => sendResponse(r))
      .catch((e) =>
        sendResponse({ ok: false, error: String(e && e.message ? e.message : e) })
      );
    return true;
  }
  if (msg.type === "record_stop") {
    recordStop(msg)
      .then((r) => sendResponse(r))
      .catch((e) =>
        sendResponse({ ok: false, error: String(e && e.message ? e.message : e) })
      );
    return true;
  }
  if (msg.type === "record_cancel") {
    recordCancel(msg)
      .then((r) => sendResponse(r))
      .catch((e) =>
        sendResponse({ ok: false, error: String(e && e.message ? e.message : e) })
      );
    return true;
  }
  if (msg.type === "record_status") {
    ensureResumed()
      .then(() => sendResponse(recordStatus(msg)))
      .catch(() => sendResponse(recordStatus(msg)));
    return true;
  }
  if (msg.type === "health") {
    healthCheck(msg.bridgeUrl || DEFAULT_BRIDGE)
      .then((r) => sendResponse(r))
      .catch((e) =>
        sendResponse({
          ok: false,
          error: String(e && e.message ? e.message : e),
          hint: "请先在本机运行: easy-rev re bridge",
        })
      );
    return true;
  }
  if (msg.type === "sign") {
    runSign(msg)
      .then((r) => sendResponse(r))
      .catch((e) =>
        sendResponse({ ok: false, error: String(e && e.message ? e.message : e) })
      );
    return true;
  }
  if (msg.type === "live_start") {
    liveStart(msg)
      .then((r) => sendResponse(r))
      .catch((e) => sendResponse({ ok: false, error: String(e) }));
    return true;
  }
  if (msg.type === "live_stop") {
    liveStop(msg)
      .then((r) => sendResponse(r))
      .catch((e) => sendResponse({ ok: false, error: String(e) }));
    return true;
  }
});

// ---------- alarms ----------

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (!alarm || !alarm.name) return;
  await ensureResumed();

  const tick = /^rec-tick-(\d+)$/.exec(alarm.name);
  if (tick) {
    const tabId = Number(tick[1]);
    const sess = recordSessions.get(tabId);
    if (!sess || sess.finalizing) return;
    await persistSessionSnapshot(tabId);
    await pushHud(tabId);
    // reschedule short tick (alarms `when` is reliable; period min=1min)
    chrome.alarms.create(`rec-tick-${tabId}`, { when: Date.now() + 2000 });
    // check idle/max in case idle alarm was missed after SW sleep
    await maybeAutoStop(tabId);
    return;
  }

  const m = /^(rec-idle|rec-max)-(\d+)$/.exec(alarm.name);
  if (!m) return;
  const kind = m[1];
  const tabId = Number(m[2]);
  const sess = recordSessions.get(tabId);
  if (!sess || sess.finalizing) return;

  if (kind === "rec-max") {
    await recordStop({ tabId, reason: "max_duration" });
    return;
  }
  await maybeAutoStop(tabId);
});

async function maybeAutoStop(tabId) {
  const sess = recordSessions.get(tabId);
  if (!sess || sess.finalizing) return;
  const now = Date.now();
  if (now - sess.startedAt >= (sess.max_s || 180) * 1000) {
    await recordStop({ tabId, reason: "max_duration" });
    return;
  }
  if (!sess.auto_idle) return;
  const idleMs = (sess.idle_s || 12) * 1000;
  const minInt = sess.min_interesting || 2;
  const quiet = now - (sess.lastInterestingAt || 0);
  if (sess.interestingCount >= minInt && quiet >= idleMs * 0.9) {
    await recordStop({ tabId, reason: "idle_quiet" });
  }
}

chrome.debugger.onDetach.addListener((source, reason) => {
  if (!source || source.tabId == null) return;
  const tabId = source.tabId;
  const sess = recordSessions.get(tabId);
  if (sess && !sess.finalizing) {
    sess.notes = sess.notes || [];
    sess.notes.push(`debugger detached: ${reason || "unknown"}`);
    // Canceled_By_User often means DevTools opened — still flush what we have
    recordStop({ tabId, reason: `detach:${reason || "unknown"}` }).catch(() => {});
  }
  liveSessions.delete(tabId);
});

// ---------- helpers ----------

async function healthCheck(bridgeUrl) {
  const url = `${String(bridgeUrl || DEFAULT_BRIDGE).replace(/\/$/, "")}/health`;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 2500);
  try {
    const r = await fetch(url, { method: "GET", signal: ctrl.signal });
    const data = await r.json();
    return data;
  } finally {
    clearTimeout(t);
  }
}

async function loadPageHooksSource() {
  const url = chrome.runtime.getURL("page_hooks.js");
  const r = await fetch(url);
  return await r.text();
}

async function dbgEval(target, expression, awaitPromise = false) {
  return await chrome.debugger.sendCommand(target, "Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise,
    userGesture: true,
  });
}

async function injectFullHooks(target) {
  const src = await loadPageHooksSource();
  const expression = `(function(){ ${src}\n; return (typeof window.__easy_rev_dump__==='function') ? {ok:true} : {ok:false}; })()`;
  const res = await dbgEval(target, expression);
  if (res && res.exceptionDetails) {
    return {
      ok: false,
      error: res.exceptionDetails.text || "inject exception",
    };
  }
  return { ok: true, result: res && res.result && res.result.value };
}

async function dumpPageHooks(target) {
  const res = await dbgEval(
    target,
    `(function(){ return typeof window.__easy_rev_dump__==='function' ? window.__easy_rev_dump__() : {installed:false,traces:[],crypto:[],signers:[]}; })()`
  );
  return (res && res.result && res.result.value) || { installed: false };
}

async function tryOracle(target, method, url, body, signerPath) {
  const payload = JSON.stringify({
    method: method || "POST",
    url: url || locationHrefFallback(url),
    body: body || { email: "probe@example.test", password: "Probe1!aaaa" },
    path: signerPath || null,
  });
  const expression = `
    (async function(){
      const args = ${payload};
      if (typeof window.__easy_rev_sign__ !== 'function') {
        return { ok:false, error:'hooks not installed' };
      }
      return await window.__easy_rev_sign__(args.method, args.url, args.body, args.path);
    })()
  `;
  try {
    const res = await dbgEval(target, expression, true);
    if (res && res.exceptionDetails) {
      return { ok: false, error: res.exceptionDetails.text || "eval error" };
    }
    return (res && res.result && res.result.value) || { ok: false, error: "empty" };
  } catch (e) {
    return { ok: false, error: String(e && e.message ? e.message : e) };
  }
}

function locationHrefFallback(u) {
  return u || "https://local/api/register";
}

function isInterestingNetwork(method, params) {
  if (
    method === "Network.webSocketFrameSent" ||
    method === "Network.webSocketFrameReceived" ||
    method === "Network.webSocketCreated" ||
    method === "Network.webSocketWillSendHandshakeRequest"
  ) {
    return true;
  }
  if (method !== "Network.requestWillBeSent" || !params) return false;
  const t = params.type || "";
  const req = params.request || {};
  const u = req.url || "";
  const m = req.method || "GET";
  if (t === "XHR" || t === "Fetch") return true;
  if (m === "POST" || m === "PUT" || m === "PATCH" || m === "DELETE") return true;
  return /\/api\/|\/rest\/|\/ws\/|graphql|livekit|imagine|media|auth|signup|register|token|stream|conversation|generate|video|voice/i.test(
    u
  );
}

async function setBadge(text, color) {
  try {
    await chrome.action.setBadgeText({ text: text || "" });
    if (color) await chrome.action.setBadgeBackgroundColor({ color });
  } catch (e) {}
}

async function setTitle(title) {
  try {
    await chrome.action.setTitle({ title: title || "Easy-Rev Reverse" });
  } catch (e) {}
}

async function persistRecordState(partial) {
  try {
    const cur = (await chrome.storage.session.get(["recordUi"])) || {};
    const next = { ...(cur.recordUi || {}), ...partial, updatedAt: Date.now() };
    await chrome.storage.session.set({ recordUi: next });
  } catch (e) {}
}

async function notify(title, message, ok = true) {
  try {
    await chrome.notifications.create(`er-${Date.now()}`, {
      type: "basic",
      iconUrl: "icons/icon128.png",
      title,
      message: String(message || "").slice(0, 180),
      priority: 2,
    });
  } catch (e) {
    // notifications permission may be missing on old install until reload
  }
  await setTitle(`${title}: ${String(message || "").slice(0, 80)}`);
}

function bindDebuggerEvents() {
  if (debuggerEventBound) return;
  debuggerEventBound = true;
  chrome.debugger.onEvent.addListener(onDebuggerEvent);
}

function onDebuggerEvent(source, method, params) {
  if (!source || source.tabId == null) return;
  const tabId = source.tabId;
  const sess = recordSessions.get(tabId);
  if (!sess || sess.finalizing) return;

  // re-inject hooks after full navigation
  if (
    sess.fullRe &&
    (method === "Page.frameNavigated" || method === "Page.navigatedWithinDocument")
  ) {
    const frame = (params && params.frame) || {};
    // only main frame full navigations for frameNavigated
    if (method === "Page.frameNavigated") {
      if (frame.parentId) {
        // iframe — skip heavy inject
      } else {
        injectFullHooks(sess.target)
          .then((inj) => {
            if (inj && inj.ok) {
              sess.hooksInjected = true;
              sess.notes.push("page_hooks re-injected after navigation");
            }
          })
          .catch(() => {});
        ensureHud(tabId).catch(() => {});
      }
    }
  }

  if (method && method.startsWith("Network.")) {
    sess.events.push({ method, params, _ts: Date.now() });
    // soft cap memory
    if (sess.events.length > 5000) {
      sess.events.splice(0, sess.events.length - 4000);
    }
    if (isInterestingNetwork(method, params)) {
      sess.interestingCount = (sess.interestingCount || 0) + 1;
      sess.lastInterestingAt = Date.now();
      if (sess.auto_idle && sess.interestingCount >= sess.min_interesting) {
        chrome.alarms.create(`rec-idle-${tabId}`, {
          when: Date.now() + sess.idle_s * 1000,
        });
      }
      const n = sess.interestingCount;
      setBadge(n > 99 ? "99+" : String(n), "#ea4335");
      persistRecordState({
        mode: "record",
        running: true,
        tabId,
        interesting: n,
        events: sess.events.length,
        message: `recording… interesting=${n} events=${sess.events.length}`,
      });
      // cheap throttle: persist every 3 interesting
      if (n % 3 === 0) persistSessionSnapshot(tabId).catch(() => {});
      pushHud(tabId).catch(() => {});
    }
  }
}

async function ensureHud(tabId) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ["hud.js"],
      world: "ISOLATED",
    });
  } catch (e) {
    // chrome:// or restricted pages
  }
}

async function pushHud(tabId, extra = {}) {
  const sess = recordSessions.get(tabId);
  const st = sess ? statusFromSess(sess) : { running: false };
  const payload = {
    type: "er_hud_update",
    phase: extra.phase || (st.running ? "recording" : "idle"),
    running: !!st.running,
    interesting: st.interesting ?? 0,
    events: st.events ?? 0,
    idle_left_s: st.idle_left_s,
    max_left_s: st.max_left_s,
    message: extra.message || st.hint || "",
    ...extra,
  };
  try {
    await chrome.tabs.sendMessage(tabId, payload);
  } catch (e) {
    // HUD not injected yet
    if (st.running) {
      await ensureHud(tabId);
      try {
        await chrome.tabs.sendMessage(tabId, payload);
      } catch (e2) {}
    }
  }
}

function statusFromSess(sess) {
  const now = Date.now();
  const elapsed_s = Math.round((now - sess.startedAt) / 1000);
  const lastAgo = Math.round((now - (sess.lastInterestingAt || sess.startedAt)) / 1000);
  let idle_left_s = null;
  if (sess.auto_idle && sess.interestingCount >= (sess.min_interesting || 2)) {
    idle_left_s = Math.max(0, (sess.idle_s || 12) - lastAgo);
  }
  const max_left_s = Math.max(0, (sess.max_s || 180) - elapsed_s);
  return {
    ok: true,
    running: true,
    tab_id: sess.tabId,
    elapsed_s,
    events: sess.events.length,
    interesting: sess.interestingCount,
    idle_s: sess.idle_s,
    max_s: sess.max_s,
    min_interesting: sess.min_interesting,
    auto_idle: sess.auto_idle,
    last_interesting_ago_s: lastAgo,
    idle_left_s,
    max_left_s,
    finalizing: !!sess.finalizing,
    hint:
      sess.interestingCount < (sess.min_interesting || 2)
        ? `再触发 ${Math.max(0, (sess.min_interesting || 2) - sess.interestingCount)} 个业务请求后启用空闲自动上传`
        : sess.auto_idle
          ? `安静 ${sess.idle_s}s 后自动上传 · 最长剩余 ${max_left_s}s`
          : `手动结束 · 最长剩余 ${max_left_s}s`,
  };
}

async function persistSessionSnapshot(tabId) {
  const sess = recordSessions.get(tabId);
  if (!sess) return;
  try {
    const all = (await chrome.storage.session.get([SESSION_STORE_KEY])) || {};
    const map = all[SESSION_STORE_KEY] || {};
    const events = sess.events.slice(-MAX_PERSIST_EVENTS);
    map[String(tabId)] = {
      tabId: sess.tabId,
      bridgeUrl: sess.bridgeUrl,
      token: sess.token,
      writePack: sess.writePack,
      packId: sess.packId,
      fullRe: sess.fullRe,
      hooksInjected: sess.hooksInjected,
      startedAt: sess.startedAt,
      lastInterestingAt: sess.lastInterestingAt,
      interestingCount: sess.interestingCount,
      idle_s: sess.idle_s,
      max_s: sess.max_s,
      min_interesting: sess.min_interesting,
      auto_idle: sess.auto_idle,
      notes: (sess.notes || []).slice(-40),
      events,
      finalizing: !!sess.finalizing,
    };
    await chrome.storage.session.set({ [SESSION_STORE_KEY]: map });
  } catch (e) {}
}

async function clearSessionSnapshot(tabId) {
  try {
    const all = (await chrome.storage.session.get([SESSION_STORE_KEY])) || {};
    const map = all[SESSION_STORE_KEY] || {};
    delete map[String(tabId)];
    await chrome.storage.session.set({ [SESSION_STORE_KEY]: map });
  } catch (e) {}
}

async function ensureResumed() {
  if (resumeAttempted && recordSessions.size > 0) {
    bindDebuggerEvents();
    return;
  }
  if (resumeAttempted) {
    bindDebuggerEvents();
    return;
  }
  resumeAttempted = true;
  bindDebuggerEvents();
  try {
    const all = (await chrome.storage.session.get([SESSION_STORE_KEY])) || {};
    const map = all[SESSION_STORE_KEY] || {};
    for (const key of Object.keys(map)) {
      const raw = map[key];
      if (!raw || raw.finalizing) continue;
      const tabId = Number(raw.tabId || key);
      if (recordSessions.has(tabId)) continue;
      // rebuild lightweight session; debugger should still be attached
      const sess = {
        tabId,
        target: { tabId },
        events: Array.isArray(raw.events) ? raw.events : [],
        bridgeUrl: raw.bridgeUrl || DEFAULT_BRIDGE,
        token: raw.token || "",
        writePack: !!raw.writePack,
        packId: raw.packId || null,
        fullRe: raw.fullRe !== false,
        hooksInjected: !!raw.hooksInjected,
        startedAt: raw.startedAt || Date.now(),
        lastInterestingAt: raw.lastInterestingAt || Date.now(),
        interestingCount: raw.interestingCount || 0,
        idle_s: raw.idle_s || 12,
        max_s: raw.max_s || 180,
        min_interesting: raw.min_interesting || 2,
        auto_idle: raw.auto_idle !== false,
        finalizing: false,
        notes: [...(raw.notes || []), "session resumed after service worker restart"],
        resumed: true,
      };
      recordSessions.set(tabId, sess);
      chrome.alarms.create(`rec-tick-${tabId}`, { when: Date.now() + 1500 });
      chrome.alarms.create(`rec-max-${tabId}`, {
        when: sess.startedAt + sess.max_s * 1000,
      });
      if (sess.auto_idle && sess.interestingCount >= sess.min_interesting) {
        const when =
          (sess.lastInterestingAt || Date.now()) + sess.idle_s * 1000;
        chrome.alarms.create(`rec-idle-${tabId}`, {
          when: Math.max(Date.now() + 500, when),
        });
      }
      setBadge(
        sess.interestingCount > 0
          ? sess.interestingCount > 99
            ? "99+"
            : String(sess.interestingCount)
          : "REC",
        "#ea4335"
      );
      ensureHud(tabId).then(() => pushHud(tabId)).catch(() => {});
    }
  } catch (e) {}
}

// kick resume ASAP
ensureResumed().catch(() => {});

async function snapshotDom(tabId) {
  try {
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        const ls = {};
        const ss = {};
        try {
          for (let i = 0; i < localStorage.length; i++) {
            const k = localStorage.key(i);
            if (k) ls[k] = String(localStorage.getItem(k) || "").slice(0, 2000);
          }
        } catch (e) {}
        try {
          for (let i = 0; i < sessionStorage.length; i++) {
            const k = sessionStorage.key(i);
            if (k) ss[k] = String(sessionStorage.getItem(k) || "").slice(0, 2000);
          }
        } catch (e) {}
        const inputs = [...document.querySelectorAll("input,textarea,select")]
          .slice(0, 80)
          .map((el, i) => ({
            i,
            tag: el.tagName.toLowerCase(),
            type: el.getAttribute("type") || "",
            name: el.getAttribute("name") || "",
            id: el.id || "",
            placeholder: el.getAttribute("placeholder") || "",
            autocomplete: el.getAttribute("autocomplete") || "",
          }));
        const buttons = [
          ...document.querySelectorAll("button,input[type=submit],input[type=button],a[role=button]"),
        ]
          .slice(0, 60)
          .map((el, i) => ({
            i,
            tag: el.tagName.toLowerCase(),
            type: el.getAttribute("type") || "",
            text: (el.innerText || el.value || "").trim().slice(0, 80),
            id: el.id || "",
            name: el.getAttribute("name") || "",
          }));
        const forms = [...document.forms].slice(0, 10).map((f, i) => ({
          i,
          id: f.id || "",
          name: f.name || "",
          action: f.action || "",
          method: f.method || "",
        }));
        const html = (document.documentElement && document.documentElement.outerHTML) || "";
        const text = (document.body && document.body.innerText) || "";
        return {
          href: location.href,
          title: document.title || "",
          inputs,
          buttons,
          forms,
          html: html.slice(0, 250000),
          visible_text: text.replace(/\s+/g, " ").trim().slice(0, 2000),
          storage: { localStorage: ls, sessionStorage: ss },
          user_agent: navigator.userAgent || "",
        };
      },
    });
    return result || {};
  } catch (e) {
    return { error: String(e && e.message ? e.message : e) };
  }
}

async function attachDebugger(tabId) {
  const target = { tabId };
  await chrome.debugger.attach(target, "1.3");
  await chrome.debugger.sendCommand(target, "Network.enable", {
    maxPostDataSize: 65536,
  });
  try {
    await chrome.debugger.sendCommand(target, "Network.setCacheDisabled", {
      cacheDisabled: true,
    });
  } catch (e) {}
  try {
    await chrome.debugger.sendCommand(target, "Runtime.enable", {});
  } catch (e) {}
  try {
    await chrome.debugger.sendCommand(target, "Page.enable", {});
  } catch (e) {}
  return target;
}

function collectInterestingRequestIds(events) {
  const requestIds = new Set();
  for (const ev of events) {
    if (ev.method === "Network.requestWillBeSent") {
      const t = (ev.params && ev.params.type) || "";
      const u = (ev.params && ev.params.request && ev.params.request.url) || "";
      const m = (ev.params && ev.params.request && ev.params.request.method) || "GET";
      if (
        t === "XHR" ||
        t === "Fetch" ||
        m === "POST" ||
        m === "PUT" ||
        m === "PATCH" ||
        m === "DELETE" ||
        /\/api\/|\/rest\/|graphql|auth|signup|register|token/i.test(u)
      ) {
        if (ev.params && ev.params.requestId) requestIds.add(ev.params.requestId);
      }
    }
  }
  return requestIds;
}

async function fetchResponseBodies(target, events, max = 50) {
  const requestIds = [...collectInterestingRequestIds(events)].slice(0, max);
  for (const rid of requestIds) {
    try {
      const body = await chrome.debugger.sendCommand(target, "Network.getResponseBody", {
        requestId: rid,
      });
      events.push({
        method: "EasyRev.responseBody",
        params: {
          requestId: rid,
          body: body && body.body,
          base64Encoded: !!(body && body.base64Encoded),
        },
        _ts: Date.now(),
      });
    } catch (e) {}
  }
}

async function postCapture(bridgeUrl, token, payload) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers["X-Easy-Rev-Token"] = token;
  const r = await fetch(`${bridgeUrl.replace(/\/$/, "")}/capture`, {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  });
  const bridgeResp = await r.json().catch(() => ({}));
  if (!r.ok) {
    return {
      ok: false,
      error: bridgeResp.error || `bridge HTTP ${r.status}`,
      bridge: bridgeResp,
    };
  }
  return { ok: true, bridge: bridgeResp, ...bridgeResp };
}

async function buildAndUploadCapture({
  tabId,
  target,
  events,
  fullRe,
  hooksInjected,
  bridgeUrl,
  token,
  writePack,
  packId,
  captureSeconds,
  notes,
  keepAttached,
}) {
  let tab = null;
  try {
    tab = await chrome.tabs.get(tabId);
  } catch (e) {}

  let pageHooks = { installed: false, traces: [], crypto: [], signers: [] };
  let oracleTry = { ok: false, error: "skipped" };
  if (fullRe) {
    try {
      pageHooks = await dumpPageHooks(target);
    } catch (e) {
      pageHooks = { installed: false, error: String(e && e.message ? e.message : e) };
    }
    try {
      // best-effort oracle against last interesting URL
      let url = (tab && tab.url) || "";
      for (let i = events.length - 1; i >= 0; i--) {
        const ev = events[i];
        if (ev.method === "Network.requestWillBeSent" && ev.params && ev.params.request) {
          const m = ev.params.request.method || "GET";
          if (m === "POST" || m === "PUT" || m === "PATCH") {
            url = ev.params.request.url || url;
            break;
          }
        }
      }
      oracleTry = await tryOracle(target, "POST", url, null, null);
    } catch (e) {
      oracleTry = { ok: false, error: String(e && e.message ? e.message : e) };
    }
  }

  try {
    await fetchResponseBodies(target, events, 50);
  } catch (e) {}

  const pageInfo = await snapshotDom(tabId);
  let cookies = [];
  try {
    cookies = await chrome.cookies.getAll({ url: tab.url || pageInfo.href || "" });
  } catch (e) {}

  if (!keepAttached) {
    try {
      await chrome.debugger.detach(target);
    } catch (e) {}
  }

  const url = (pageInfo && pageInfo.href) || (tab && tab.url) || "";
  const title = (pageInfo && pageInfo.title) || (tab && tab.title) || "";
  const payload = {
    source: "easy-rev-chrome",
    version: "0.3.0",
    url,
    title,
    tab_id: tabId,
    user_agent: (pageInfo && pageInfo.user_agent) || "",
    capture_seconds: captureSeconds,
    debugger_attached: true,
    hooks_injected: !!hooksInjected,
    cookies,
    storage: (pageInfo && pageInfo.storage) || {},
    html: (pageInfo && pageInfo.html) || "",
    visible_text: (pageInfo && pageInfo.visible_text) || "",
    inputs: (pageInfo && pageInfo.inputs) || [],
    buttons: (pageInfo && pageInfo.buttons) || [],
    forms: (pageInfo && pageInfo.forms) || [],
    network_events: events,
    page_hooks: pageHooks,
    oracle_try: oracleTry,
    write_pack: !!writePack,
    pack_id: packId || null,
    notes: notes || [],
    full_re: !!fullRe,
  };

  const uploaded = await postCapture(bridgeUrl, token, payload);
  if (!uploaded.ok) {
    return {
      ...uploaded,
      events: events.length,
      hooks_injected: !!hooksInjected,
      page_hooks: {
        traces: (pageHooks.traces && pageHooks.traces.length) || 0,
        crypto: (pageHooks.crypto && pageHooks.crypto.length) || 0,
        signers: (pageHooks.signers && pageHooks.signers.length) || 0,
      },
      oracle_try: oracleTry,
      parity: fullRe ? "near-camoufox" : "network",
    };
  }
  return {
    ok: true,
    tab: { id: tabId, url, title },
    events: events.length,
    hooks_injected: !!hooksInjected,
    page_hooks: {
      traces: (pageHooks.traces && pageHooks.traces.length) || 0,
      crypto: (pageHooks.crypto && pageHooks.crypto.length) || 0,
      signers: (pageHooks.signers && pageHooks.signers.length) || 0,
    },
    oracle_try: oracleTry,
    bridge: uploaded.bridge || uploaded,
    capture_path: (uploaded.bridge && uploaded.bridge.capture_path) || uploaded.capture_path,
    parity: fullRe ? "near-camoufox" : "network",
  };
}

// ---------- modes ----------

async function runAnalyze(opts) {
  await ensureResumed();
  const bridgeUrl = (opts.bridgeUrl || DEFAULT_BRIDGE).replace(/\/$/, "");
  const seconds = Math.min(Math.max(Number(opts.seconds) || 15, 3), 300);
  const writePack = !!opts.writePack;
  const packId = opts.packId || null;
  const token = opts.token || "";
  const fullRe = opts.fullRe !== false;

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || tab.id == null) return { ok: false, error: "no active tab" };
  const tabId = tab.id;

  if (recordSessions.has(tabId)) {
    return { ok: false, error: "recording in progress on this tab; stop it first" };
  }

  const target = { tabId };
  const buf = { events: [] };
  const onEvent = (source, method, params) => {
    if (!source || source.tabId !== tabId) return;
    if (method && method.startsWith("Network.")) {
      buf.events.push({ method, params, _ts: Date.now() });
    }
  };
  chrome.debugger.onEvent.addListener(onEvent);

  let hooksInjected = false;
  try {
    await attachDebugger(tabId);
    if (fullRe) {
      const inj = await injectFullHooks(target);
      hooksInjected = !!(inj && inj.ok);
    }
  } catch (e) {
    chrome.debugger.onEvent.removeListener(onEvent);
    return {
      ok: false,
      error: `debugger attach failed: ${e && e.message ? e.message : e}`,
      hint: "请关闭该标签页的 DevTools 后重试。",
    };
  }

  await setBadge("…", "#4285f4");
  await ensureHud(tabId);
  await pushHud(tabId, {
    phase: "recording",
    interesting: 0,
    events: 0,
    message: `定时分析 ${seconds}s…`,
    idle_left_s: seconds,
    max_left_s: seconds,
  });

  await sleep(seconds * 1000);
  chrome.debugger.onEvent.removeListener(onEvent);

  const result = await buildAndUploadCapture({
    tabId,
    target,
    events: buf.events,
    fullRe,
    hooksInjected,
    bridgeUrl,
    token,
    writePack,
    packId,
    captureSeconds: seconds,
    notes: ["extension timed analyze", hooksInjected ? "page_hooks injected" : "page_hooks skipped"],
    keepAttached: false,
  });

  await setBadge(result.ok ? "OK" : "ERR", result.ok ? "#34a853" : "#ea4335");
  await pushHud(tabId, {
    phase: result.ok ? "ok" : "err",
    message: result.ok
      ? `定时分析完成 · ${result.events || 0} events`
      : result.error || "failed",
  });
  if (result.ok) {
    await notify("Easy-Rev 分析完成", humanResult(result), true);
  } else {
    await notify("Easy-Rev 分析失败", result.error || "unknown", false);
  }
  setTimeout(() => setBadge("", null), 4000);
  return { ...result, mode: "timed" };
}

async function recordStart(opts) {
  await ensureResumed();
  const bridgeUrl = (opts.bridgeUrl || DEFAULT_BRIDGE).replace(/\/$/, "");
  const token = opts.token || "";
  const fullRe = opts.fullRe !== false;
  const writePack = !!opts.writePack;
  const packId = opts.packId || null;
  const idle_s = Math.min(Math.max(Number(opts.idle_s) || 12, 3), 120);
  const max_s = Math.min(Math.max(Number(opts.max_s) || 180, 15), 900);
  const min_interesting = Math.min(Math.max(Number(opts.min_interesting) || 2, 0), 50);
  const auto_idle = opts.auto_idle !== false;

  // preflight bridge so user fails fast
  try {
    const h = await healthCheck(bridgeUrl);
    if (!h || h.ok === false) {
      return {
        ok: false,
        error: (h && h.error) || "bridge unavailable",
        hint: "请先运行: easy-rev re bridge",
      };
    }
  } catch (e) {
    return {
      ok: false,
      error: `无法连接 Bridge: ${e && e.message ? e.message : e}`,
      hint: "请先在本机终端运行: easy-rev re bridge",
    };
  }

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || tab.id == null) return { ok: false, error: "no active tab" };
  const tabId = tab.id;

  if (recordSessions.has(tabId)) {
    return {
      ok: true,
      already: true,
      ...recordStatus({ tabId }),
    };
  }

  const target = { tabId };
  let hooksInjected = false;
  bindDebuggerEvents();
  try {
    await attachDebugger(tabId);
    if (fullRe) {
      const inj = await injectFullHooks(target);
      hooksInjected = !!(inj && inj.ok);
    }
  } catch (e) {
    return {
      ok: false,
      error: `debugger attach failed: ${e && e.message ? e.message : e}`,
      hint: "请关闭该标签页的 DevTools 后重试。Chrome 顶部若提示「正在调试」也请先结束其它调试。",
    };
  }

  const sess = {
    tabId,
    target,
    events: [],
    bridgeUrl,
    token,
    writePack,
    packId,
    fullRe,
    hooksInjected,
    startedAt: Date.now(),
    lastInterestingAt: Date.now(),
    interestingCount: 0,
    idle_s,
    max_s,
    min_interesting,
    auto_idle,
    finalizing: false,
    notes: [
      "extension record mode v0.3",
      hooksInjected ? "page_hooks injected" : "page_hooks skipped",
      `idle_s=${idle_s} max_s=${max_s} min_interesting=${min_interesting} auto_idle=${auto_idle}`,
    ],
  };
  recordSessions.set(tabId, sess);

  chrome.alarms.create(`rec-max-${tabId}`, { when: Date.now() + max_s * 1000 });
  chrome.alarms.create(`rec-tick-${tabId}`, { when: Date.now() + 2000 });

  await setBadge("REC", "#ea4335");
  await setTitle("Easy-Rev 录制中 — 可关弹窗，在页面操作");
  await persistRecordState({
    mode: "record",
    running: true,
    tabId,
    idle_s,
    max_s,
    interesting: 0,
    events: 0,
    message: "recording — operate the site, will auto-upload after idle",
  });
  await persistSessionSnapshot(tabId);
  await ensureHud(tabId);
  await pushHud(tabId, {
    phase: "recording",
    message: "已开始录制：正常操作页面即可，可关闭扩展弹窗",
  });

  return {
    ok: true,
    mode: "record",
    tab_id: tabId,
    url: tab.url,
    idle_s,
    max_s,
    min_interesting,
    auto_idle,
    hooks_injected: hooksInjected,
    hint: "在页面自由操作。空闲后自动上传，或点 HUD / 弹窗「结束并上传」。",
  };
}

async function recordStop(opts) {
  await ensureResumed();
  const reason = opts.reason || "manual";
  let tabId = opts.tabId;
  if (tabId == null) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || tab.id == null) {
      const first = recordSessions.keys().next();
      if (first.done) return { ok: false, error: "no recording session" };
      tabId = first.value;
    } else if (recordSessions.has(tab.id)) {
      tabId = tab.id;
    } else {
      const first = recordSessions.keys().next();
      if (first.done) return { ok: false, error: "no recording session" };
      tabId = first.value;
    }
  }

  const sess = recordSessions.get(tabId);
  if (!sess) {
    return { ok: false, error: "no recording session on this tab" };
  }
  if (sess.finalizing) {
    return { ok: true, already_finalizing: true, tab_id: tabId };
  }
  sess.finalizing = true;

  try {
    await chrome.alarms.clear(`rec-idle-${tabId}`);
    await chrome.alarms.clear(`rec-max-${tabId}`);
    await chrome.alarms.clear(`rec-tick-${tabId}`);
  } catch (e) {}

  const elapsed_s = Math.max(1, Math.round((Date.now() - sess.startedAt) / 1000));
  sess.notes.push(`stop_reason=${reason}`);
  sess.notes.push(`interesting=${sess.interestingCount} events=${sess.events.length}`);

  await setBadge("…", "#4285f4");
  await persistRecordState({
    mode: "record",
    running: false,
    finalizing: true,
    message: `uploading… reason=${reason}`,
  });
  await pushHud(tabId, {
    phase: "uploading",
    message: stopReasonLabel(reason) + " · 正在上传到 Bridge…",
    interesting: sess.interestingCount,
    events: sess.events.length,
  });

  let result;
  try {
    result = await buildAndUploadCapture({
      tabId,
      target: sess.target,
      events: sess.events,
      fullRe: sess.fullRe,
      hooksInjected: sess.hooksInjected,
      bridgeUrl: sess.bridgeUrl,
      token: sess.token,
      writePack: sess.writePack,
      packId: sess.packId,
      captureSeconds: elapsed_s,
      notes: sess.notes,
      keepAttached: false,
    });
  } catch (e) {
    result = { ok: false, error: String(e && e.message ? e.message : e) };
    try {
      await chrome.debugger.detach(sess.target);
    } catch (e2) {}
  }

  recordSessions.delete(tabId);
  await clearSessionSnapshot(tabId);

  result = {
    ...result,
    mode: "record",
    stop_reason: reason,
    interesting: sess.interestingCount,
    elapsed_s,
  };

  await setBadge(result.ok ? "OK" : "ERR", result.ok ? "#34a853" : "#ea4335");
  await persistRecordState({
    mode: "record",
    running: false,
    finalizing: false,
    lastResult: result,
    message: result.ok
      ? `uploaded · reason=${reason} · events=${result.events} · ${result.bridge && result.bridge.capture_path}`
      : result.error,
  });
  await pushHud(tabId, {
    phase: result.ok ? "ok" : "err",
    interesting: sess.interestingCount,
    events: result.events || sess.events.length,
    message: result.ok
      ? humanResult(result)
      : result.error || "upload failed",
  });
  if (result.ok) {
    await notify("Easy-Rev 录制完成", humanResult(result), true);
  } else {
    await notify("Easy-Rev 上传失败", result.error || "unknown", false);
  }
  setTimeout(() => setBadge("", null), 5000);
  return result;
}

async function recordCancel(opts) {
  await ensureResumed();
  let tabId = opts && opts.tabId;
  if (tabId == null) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.id != null && recordSessions.has(tab.id)) tabId = tab.id;
    else {
      const first = recordSessions.keys().next();
      if (first.done) return { ok: false, error: "no recording session" };
      tabId = first.value;
    }
  }
  const sess = recordSessions.get(tabId);
  if (!sess) return { ok: false, error: "no recording session" };
  if (sess.finalizing) return { ok: true, already_finalizing: true };

  sess.finalizing = true;
  try {
    await chrome.alarms.clear(`rec-idle-${tabId}`);
    await chrome.alarms.clear(`rec-max-${tabId}`);
    await chrome.alarms.clear(`rec-tick-${tabId}`);
  } catch (e) {}
  try {
    await chrome.debugger.detach(sess.target || { tabId });
  } catch (e) {}
  recordSessions.delete(tabId);
  await clearSessionSnapshot(tabId);
  await setBadge("", null);
  await persistRecordState({
    mode: "record",
    running: false,
    finalizing: false,
    lastResult: { ok: true, cancelled: true },
    message: "cancelled",
  });
  await pushHud(tabId, {
    phase: "cancelled",
    message: "已取消，未上传",
  });
  await notify("Easy-Rev 已取消", "录制已取消，未上传 capture", false);
  return { ok: true, cancelled: true, tab_id: tabId };
}

function recordStatus(opts) {
  let tabId = opts && opts.tabId;
  if (tabId == null) {
    const it = recordSessions.keys().next();
    if (!it.done) tabId = it.value;
  }
  if (tabId == null || !recordSessions.has(tabId)) {
    return {
      ok: true,
      running: false,
      sessions: recordSessions.size,
    };
  }
  return statusFromSess(recordSessions.get(tabId));
}

function stopReasonLabel(reason) {
  const r = String(reason || "");
  if (r === "idle_quiet") return "空闲自动结束";
  if (r === "max_duration") return "到达最长录制时间";
  if (r === "manual" || r === "hud_manual") return "手动结束";
  if (r.startsWith("detach:")) return "调试器断开（可能打开了 DevTools）";
  return r;
}

function humanResult(result) {
  if (!result) return "无结果";
  if (!result.ok) return result.error || "失败";
  const path =
    (result.bridge && (result.bridge.capture_path || result.bridge.path)) ||
    result.capture_path ||
    "";
  const short = path ? path.split(/[/\\]/).slice(-1)[0] : "capture saved";
  const interesting = result.interesting != null ? result.interesting : "?";
  const events = result.events != null ? result.events : "?";
  const why = stopReasonLabel(result.stop_reason || "manual");
  return `${why} · 业务 ${interesting} / 事件 ${events} · ${short}`;
}

// ---------- Live / sign (oracle) ----------

async function runSign(opts) {
  await ensureResumed();
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || tab.id == null) return { ok: false, error: "no active tab" };
  const target = { tabId: tab.id };
  let attached = false;
  try {
    if (!liveSessions.has(tab.id) && !recordSessions.has(tab.id)) {
      await chrome.debugger.attach(target, "1.3");
      attached = true;
      try {
        await chrome.debugger.sendCommand(target, "Runtime.enable", {});
      } catch (e) {}
      await injectFullHooks(target);
    }
    const body = opts.json || opts.body || {};
    const result = await tryOracle(
      target,
      opts.method || "POST",
      opts.url || tab.url,
      body,
      opts.signer_path || null
    );
    return { ok: !!result.ok, ...result };
  } catch (e) {
    return { ok: false, error: String(e && e.message ? e.message : e) };
  } finally {
    if (attached && !liveSessions.has(tab.id) && !recordSessions.has(tab.id)) {
      try {
        await chrome.debugger.detach(target);
      } catch (e) {}
    }
  }
}

async function liveStart(opts) {
  await ensureResumed();
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || tab.id == null) return { ok: false, error: "no active tab" };
  const target = { tabId: tab.id };
  if (liveSessions.has(tab.id) || recordSessions.has(tab.id)) {
    return { ok: true, already: true, tab_id: tab.id, url: tab.url };
  }
  try {
    await chrome.debugger.attach(target, "1.3");
    try {
      await chrome.debugger.sendCommand(target, "Runtime.enable", {});
    } catch (e) {}
    await chrome.debugger.sendCommand(target, "Network.enable", {
      maxPostDataSize: 65536,
    });
    await injectFullHooks(target);
    liveSessions.set(tab.id, { target, started: Date.now() });
    return { ok: true, tab_id: tab.id, url: tab.url, hooks: true };
  } catch (e) {
    return { ok: false, error: String(e && e.message ? e.message : e) };
  }
}

async function liveStop(opts) {
  const tabId = opts.tabId;
  const [tab] = tabId
    ? [{ id: tabId }]
    : await chrome.tabs.query({ active: true, currentWindow: true });
  const id = tab && tab.id;
  if (id == null) return { ok: false, error: "no tab" };
  const sess = liveSessions.get(id);
  if (sess) {
    try {
      await chrome.debugger.detach(sess.target || { tabId: id });
    } catch (e) {}
    liveSessions.delete(id);
  }
  return { ok: true, stopped: true, tab_id: id };
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
