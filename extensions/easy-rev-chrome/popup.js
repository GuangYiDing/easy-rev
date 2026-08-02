const $ = (id) => document.getElementById(id);
const statusEl = $("status");
const bridgeChip = $("bridgeChip");

function setStatus(text, cls) {
  statusEl.textContent = text;
  statusEl.className = cls || "";
}

function setRecUi(running) {
  $("recStart").disabled = !!running;
  $("recStop").disabled = !running;
  $("recCancel").disabled = !running;
  $("metrics").hidden = !running;
  if (running) {
    bridgeChip.textContent = "REC";
    bridgeChip.className = "chip rec";
    $("heroTitle").textContent = "录制进行中";
    $("heroDesc").textContent = "可关闭弹窗，在页面正常操作。页内右下角有 HUD。";
  }
}

function formatSecs(n) {
  if (n == null || Number.isNaN(n)) return "–";
  return `${Math.max(0, Math.round(n))}s`;
}

function formatResult(resp) {
  if (!resp) return "无响应";
  if (resp.cancelled) return "已取消，未上传。";
  if (!resp.ok) {
    return `失败：${resp.error || "unknown"}${resp.hint ? "\n" + resp.hint : ""}`;
  }
  const b = resp.bridge || {};
  const ph = resp.page_hooks || {};
  const why = {
    idle_quiet: "空闲自动结束",
    max_duration: "到达最长录制时间",
    manual: "手动结束",
    hud_manual: "页内 HUD 结束",
  }[resp.stop_reason] || resp.stop_reason || "完成";
  const path = b.capture_path || b.path || resp.capture_path || "（见 bridge status）";
  const lines = [
    `✅ ${why}`,
    `业务请求 ${resp.interesting ?? "?"} · 事件 ${resp.events ?? "?"} · 用时 ${resp.elapsed_s ?? "?"}s`,
    `hooks traces=${ph.traces ?? "?"} crypto=${ph.crypto ?? "?"}`,
    `capture: ${path}`,
  ];
  if (b.pack && b.pack.pack_path) lines.push(`pack: ${b.pack.pack_path}`);
  if (b.next && b.next.length) lines.push("", "下一步:", ...b.next.slice(0, 4));
  else {
    lines.push("", "下一步: easy-rev ai call re.bridge.status -i '{}'");
  }
  return lines.join("\n");
}

const STORAGE_KEYS = [
  "bridgeUrl",
  "token",
  "seconds",
  "idle_s",
  "max_s",
  "min_interesting",
  "autoIdle",
  "writePack",
  "packId",
  "fullRe",
];

chrome.storage.local.get(STORAGE_KEYS, (s) => {
  if (s.bridgeUrl) $("bridge").value = s.bridgeUrl;
  if (s.token) $("token").value = s.token;
  if (s.seconds) $("seconds").value = s.seconds;
  if (s.idle_s) $("idle_s").value = s.idle_s;
  if (s.max_s) $("max_s").value = s.max_s;
  if (s.min_interesting != null) $("min_interesting").value = s.min_interesting;
  if (s.autoIdle === false) $("autoIdle").checked = false;
  if (s.writePack) $("writePack").checked = !!s.writePack;
  if (s.packId) $("packId").value = s.packId;
  if (s.fullRe === false) $("fullRe").checked = false;
  // auto health after settings restored
  checkBridge(true);
});

function persist() {
  chrome.storage.local.set({
    bridgeUrl: $("bridge").value.trim(),
    token: $("token").value.trim(),
    seconds: Number($("seconds").value) || 30,
    idle_s: Number($("idle_s").value) || 12,
    max_s: Number($("max_s").value) || 180,
    min_interesting: Number($("min_interesting").value) || 2,
    autoIdle: $("autoIdle").checked,
    writePack: $("writePack").checked,
    packId: $("packId").value.trim(),
    fullRe: $("fullRe").checked,
  });
}

function commonOpts() {
  return {
    bridgeUrl: $("bridge").value.trim(),
    token: $("token").value.trim(),
    writePack: $("writePack").checked,
    packId: $("packId").value.trim() || null,
    fullRe: $("fullRe").checked,
  };
}

function applyLiveStatus(resp) {
  if (!resp) return;
  if (resp.running) {
    setRecUi(true);
    $("mInteresting").textContent = String(resp.interesting ?? 0);
    $("mEvents").textContent = String(resp.events ?? 0);
    const idlePart =
      resp.idle_left_s != null ? `空闲 ${formatSecs(resp.idle_left_s)}` : "等待业务流量";
    const maxPart = resp.max_left_s != null ? `最长 ${formatSecs(resp.max_left_s)}` : "";
    $("mIdle").textContent =
      resp.idle_left_s != null ? formatSecs(resp.idle_left_s) : "–";
    setStatus(
      `录制中 tab=${resp.tab_id}\n` +
        `业务 ${resp.interesting ?? 0} · 事件 ${resp.events ?? 0} · 已录 ${resp.elapsed_s ?? 0}s\n` +
        `${idlePart}${maxPart ? " · " + maxPart : ""}\n` +
        (resp.hint || "可关弹窗；页内 HUD 可结束/取消"),
      "rec"
    );
  } else {
    setRecUi(false);
  }
}

function refreshStatusFromBackground() {
  chrome.runtime.sendMessage({ type: "record_status" }, (resp) => {
    if (chrome.runtime.lastError || !resp) return;
    applyLiveStatus(resp);
  });
}

function checkBridge(silent) {
  const url = $("bridge").value.trim();
  if (!silent) setStatus("检查 Bridge…");
  bridgeChip.textContent = "Bridge…";
  bridgeChip.className = "chip wait";
  chrome.runtime.sendMessage({ type: "health", bridgeUrl: url }, (resp) => {
    if (chrome.runtime.lastError) {
      bridgeChip.textContent = "Bridge ✗";
      bridgeChip.className = "chip err";
      if (!silent) setStatus(chrome.runtime.lastError.message, "err");
      return;
    }
    if (resp && resp.ok !== false && !resp.error && (resp.ok === true || resp.port != null || resp.service)) {
      const recording = !$("recStop").disabled;
      if (!recording) {
        bridgeChip.textContent = "Bridge ✓";
        bridgeChip.className = "chip ok";
      }
      if (!silent) {
        setStatus(
          `Bridge 正常 · port=${resp.port || "?"} · 已收 capture=${resp.count ?? 0}`,
          "ok"
        );
      } else if (!recording) {
        $("heroTitle").textContent = "可以开始";
        $("heroDesc").textContent =
          "点「开始录制」后，在页面里触发目标操作；安静后会自动上传。";
      }
      return;
    }
    bridgeChip.textContent = "Bridge ✗";
    bridgeChip.className = "chip err";
    $("heroTitle").textContent = "Bridge 未连接";
    $("heroDesc").textContent = "请先在本机运行 easy-rev re bridge";
    setStatus(
      `Bridge 不可用\n请先运行: easy-rev re bridge\n默认: http://127.0.0.1:18766\n${
        (resp && resp.error) || ""
      }`,
      "err"
    );
  });
}

// restore last result if popup reopened
try {
  chrome.storage.session.get(["recordUi"], (s) => {
    const ui = s && s.recordUi;
    if (!ui) return;
    if (ui.running) {
      setRecUi(true);
      setStatus(ui.message || "recording…", "rec");
    } else if (ui.lastResult) {
      setRecUi(false);
      setStatus(formatResult(ui.lastResult), ui.lastResult.ok ? "ok" : "err");
      if (ui.lastResult.ok) {
        $("heroTitle").textContent = "上一轮已完成";
        $("heroDesc").textContent = "可继续录制，或用 CLI 读取 capture。";
      }
    } else if (ui.message) {
      setStatus(ui.message, "");
    }
  });
} catch (e) {}

refreshStatusFromBackground();
const poll = setInterval(refreshStatusFromBackground, 1200);
window.addEventListener("unload", () => clearInterval(poll));

$("health").addEventListener("click", () => {
  persist();
  checkBridge(false);
});

$("recStart").addEventListener("click", () => {
  persist();
  setStatus("附着 debugger + 注入 hooks…", "rec");
  setRecUi(true);
  chrome.runtime.sendMessage(
    {
      type: "record_start",
      ...commonOpts(),
      idle_s: Number($("idle_s").value) || 12,
      max_s: Number($("max_s").value) || 180,
      min_interesting: Number($("min_interesting").value) || 2,
      auto_idle: $("autoIdle").checked,
    },
    (resp) => {
      if (chrome.runtime.lastError) {
        setRecUi(false);
        setStatus(chrome.runtime.lastError.message, "err");
        return;
      }
      if (!resp || !resp.ok) {
        setRecUi(false);
        setStatus(
          `无法开始: ${(resp && resp.error) || "unknown"}\n${(resp && resp.hint) || ""}`,
          "err"
        );
        checkBridge(true);
        return;
      }
      setStatus(
        `录制已开始\n${resp.hint || ""}\nhooks=${resp.hooks_injected ? "on" : "off"} idle=${resp.idle_s}s max=${resp.max_s}s`,
        "rec"
      );
      refreshStatusFromBackground();
    }
  );
});

$("recStop").addEventListener("click", () => {
  setStatus("结束并上传中…", "rec");
  chrome.runtime.sendMessage({ type: "record_stop", reason: "manual" }, (resp) => {
    setRecUi(false);
    if (chrome.runtime.lastError) {
      setStatus(chrome.runtime.lastError.message, "err");
      return;
    }
    setStatus(formatResult(resp), resp && resp.ok ? "ok" : "err");
    if (resp && resp.ok) {
      $("heroTitle").textContent = "上传完成";
      $("heroDesc").textContent = "可用 re.bridge.status 查看 capture 路径。";
      bridgeChip.textContent = "Bridge ✓";
      bridgeChip.className = "chip ok";
    }
  });
});

$("recCancel").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "record_cancel" }, (resp) => {
    setRecUi(false);
    if (chrome.runtime.lastError) {
      setStatus(chrome.runtime.lastError.message, "err");
      return;
    }
    setStatus((resp && resp.ok && "已取消，未上传。") || formatResult(resp), "");
    $("heroTitle").textContent = "已取消";
    $("heroDesc").textContent = "没有数据上传到 Bridge。";
    checkBridge(true);
  });
});

$("go").addEventListener("click", () => {
  persist();
  setStatus("定时分析中…请稍候不要关弹窗", "");
  chrome.runtime.sendMessage(
    {
      type: "analyze",
      ...commonOpts(),
      seconds: Number($("seconds").value) || 30,
    },
    (resp) => {
      if (chrome.runtime.lastError) {
        setStatus(chrome.runtime.lastError.message, "err");
        return;
      }
      setStatus(formatResult(resp), resp && resp.ok ? "ok" : "err");
    }
  );
});

$("live").addEventListener("click", () => {
  persist();
  chrome.runtime.sendMessage({ type: "live_start", ...commonOpts() }, (resp) => {
    if (chrome.runtime.lastError) {
      setStatus(chrome.runtime.lastError.message, "err");
      return;
    }
    setStatus(
      resp && resp.ok
        ? `已保持附着 tab=${resp.tab_id}\n可点「试签」`
        : `附着失败: ${(resp && resp.error) || "unknown"}`,
      resp && resp.ok ? "ok" : "err"
    );
  });
});

$("sign").addEventListener("click", () => {
  persist();
  setStatus("试签中…");
  chrome.runtime.sendMessage({ type: "sign", ...commonOpts() }, (resp) => {
    if (chrome.runtime.lastError) {
      setStatus(chrome.runtime.lastError.message, "err");
      return;
    }
    setStatus(
      resp && resp.ok
        ? `试签成功\npath=${resp.path || "?"}\n${JSON.stringify(resp.headers || resp.result || resp, null, 0).slice(0, 400)}`
        : `试签失败: ${(resp && resp.error) || "unknown"}`,
      resp && resp.ok ? "ok" : "err"
    );
  });
});

// persist on blur of settings fields
["bridge", "token", "idle_s", "max_s", "min_interesting", "seconds", "packId"].forEach((id) => {
  $(id).addEventListener("change", persist);
});
["autoIdle", "fullRe", "writePack"].forEach((id) => {
  $(id).addEventListener("change", persist);
});
