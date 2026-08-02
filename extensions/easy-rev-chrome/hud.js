/**
 * In-page recording HUD. Injected via chrome.scripting; idempotent.
 * Messages:
 *  - er_hud_update { running, interesting, events, idle_left_s, max_left_s, phase, message }
 *  - er_hud_hide
 */
(function () {
  if (window.__easy_rev_hud__) return;
  window.__easy_rev_hud__ = true;

  const ROOT_ID = "easy-rev-hud-root";
  const STYLE_ID = "easy-rev-hud-style";

  function ensureDom() {
    if (document.getElementById(ROOT_ID)) return document.getElementById(ROOT_ID);
    if (!document.getElementById(STYLE_ID)) {
      const style = document.createElement("style");
      style.id = STYLE_ID;
      style.textContent = `
        #${ROOT_ID} {
          all: initial;
          position: fixed;
          z-index: 2147483646;
          right: 16px;
          bottom: 16px;
          font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif;
          color: #e7ecf3;
          user-select: none;
        }
        #${ROOT_ID} * { box-sizing: border-box; font-family: inherit; }
        #${ROOT_ID} .er-card {
          min-width: 220px;
          max-width: 280px;
          background: rgba(15, 20, 25, 0.94);
          border: 1px solid rgba(66, 133, 244, 0.45);
          border-radius: 14px;
          box-shadow: 0 10px 40px rgba(0,0,0,.45);
          backdrop-filter: blur(10px);
          padding: 12px 12px 10px;
        }
        #${ROOT_ID} .er-head {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-bottom: 8px;
        }
        #${ROOT_ID} .er-dot {
          width: 9px; height: 9px; border-radius: 50%;
          background: #ea4335;
          box-shadow: 0 0 0 0 rgba(234,67,53,.6);
          animation: er-pulse 1.4s infinite;
        }
        #${ROOT_ID} .er-dot.up { background: #4285f4; animation: none; }
        #${ROOT_ID} .er-dot.ok { background: #34a853; animation: none; }
        #${ROOT_ID} .er-dot.err { background: #ea4335; animation: none; }
        @keyframes er-pulse {
          0% { box-shadow: 0 0 0 0 rgba(234,67,53,.55); }
          70% { box-shadow: 0 0 0 10px rgba(234,67,53,0); }
          100% { box-shadow: 0 0 0 0 rgba(234,67,53,0); }
        }
        #${ROOT_ID} .er-title { font-size: 13px; font-weight: 700; color: #e7ecf3; }
        #${ROOT_ID} .er-sub { font-size: 11px; color: #8b9bb4; margin-top: 2px; line-height: 1.35; }
        #${ROOT_ID} .er-stats {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 6px;
          margin: 10px 0;
        }
        #${ROOT_ID} .er-stat {
          background: #1a2332;
          border-radius: 8px;
          padding: 6px 8px;
        }
        #${ROOT_ID} .er-stat b {
          display: block;
          font-size: 14px;
          color: #fff;
          font-weight: 700;
        }
        #${ROOT_ID} .er-stat span {
          font-size: 10px;
          color: #8b9bb4;
        }
        #${ROOT_ID} .er-actions { display: flex; gap: 6px; }
        #${ROOT_ID} button {
          flex: 1;
          border: 0;
          border-radius: 8px;
          padding: 7px 8px;
          font-size: 11px;
          font-weight: 650;
          cursor: pointer;
          color: #fff;
        }
        #${ROOT_ID} .er-stop { background: #c5221f; }
        #${ROOT_ID} .er-cancel { background: #2a3548; }
        #${ROOT_ID} .er-hide {
          position: absolute;
          top: 6px; right: 8px;
          background: transparent;
          border: 0;
          color: #8b9bb4;
          font-size: 14px;
          cursor: pointer;
          padding: 2px 6px;
          flex: none;
        }
        #${ROOT_ID}.er-min .er-card { min-width: 0; padding: 8px 10px; }
        #${ROOT_ID}.er-min .er-stats,
        #${ROOT_ID}.er-min .er-actions,
        #${ROOT_ID}.er-min .er-sub { display: none; }
      `;
      (document.documentElement || document.head).appendChild(style);
    }

    const root = document.createElement("div");
    root.id = ROOT_ID;
    root.innerHTML = `
      <div class="er-card">
        <button class="er-hide" type="button" title="最小化">–</button>
        <div class="er-head">
          <div class="er-dot" data-role="dot"></div>
          <div>
            <div class="er-title" data-role="title">Easy-Rev 录制中</div>
            <div class="er-sub" data-role="sub">在页面里正常操作即可</div>
          </div>
        </div>
        <div class="er-stats">
          <div class="er-stat"><b data-role="interesting">0</b><span>业务请求</span></div>
          <div class="er-stat"><b data-role="events">0</b><span>总事件</span></div>
          <div class="er-stat"><b data-role="idle">–</b><span>空闲倒计时</span></div>
          <div class="er-stat"><b data-role="max">–</b><span>最长剩余</span></div>
        </div>
        <div class="er-actions">
          <button class="er-stop" type="button" data-role="stop">结束并上传</button>
          <button class="er-cancel" type="button" data-role="cancel">取消</button>
        </div>
      </div>
    `;
    (document.documentElement || document.body).appendChild(root);

    root.querySelector('[data-role="stop"]').addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "record_stop", reason: "hud_manual" });
    });
    root.querySelector('[data-role="cancel"]').addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "record_cancel" });
    });
    root.querySelector(".er-hide").addEventListener("click", () => {
      root.classList.toggle("er-min");
    });

    // drag
    let drag = null;
    const card = root.querySelector(".er-card");
    card.addEventListener("mousedown", (e) => {
      if (e.target.closest("button")) return;
      drag = {
        x: e.clientX,
        y: e.clientY,
        right: parseInt(getComputedStyle(root).right, 10) || 16,
        bottom: parseInt(getComputedStyle(root).bottom, 10) || 16,
      };
      e.preventDefault();
    });
    window.addEventListener("mousemove", (e) => {
      if (!drag) return;
      const dx = e.clientX - drag.x;
      const dy = e.clientY - drag.y;
      root.style.right = Math.max(8, drag.right - dx) + "px";
      root.style.bottom = Math.max(8, drag.bottom - dy) + "px";
      root.style.left = "auto";
      root.style.top = "auto";
    });
    window.addEventListener("mouseup", () => {
      drag = null;
    });

    return root;
  }

  function fmt(n) {
    if (n == null || Number.isNaN(n)) return "–";
    if (n < 0) return "0s";
    return `${Math.round(n)}s`;
  }

  function update(msg) {
    const root = ensureDom();
    root.style.display = "block";
    const phase = msg.phase || (msg.running ? "recording" : "idle");
    const dot = root.querySelector('[data-role="dot"]');
    const title = root.querySelector('[data-role="title"]');
    const sub = root.querySelector('[data-role="sub"]');
    dot.className = "er-dot";
    if (phase === "uploading") {
      dot.classList.add("up");
      title.textContent = "正在上传…";
    } else if (phase === "ok") {
      dot.classList.add("ok");
      title.textContent = "上传成功";
    } else if (phase === "err") {
      dot.classList.add("err");
      title.textContent = "上传失败";
    } else if (phase === "cancelled") {
      dot.classList.add("err");
      title.textContent = "已取消";
    } else {
      title.textContent = "Easy-Rev 录制中";
    }
    sub.textContent = msg.message || "在页面里正常操作；安静后会自动上传";
    root.querySelector('[data-role="interesting"]').textContent = String(msg.interesting ?? 0);
    root.querySelector('[data-role="events"]').textContent = String(msg.events ?? 0);
    root.querySelector('[data-role="idle"]').textContent = fmt(msg.idle_left_s);
    root.querySelector('[data-role="max"]').textContent = fmt(msg.max_left_s);

    const actions = root.querySelector(".er-actions");
    if (phase === "recording") {
      actions.style.display = "flex";
    } else {
      actions.style.display = "none";
    }

    if (phase === "ok" || phase === "err" || phase === "cancelled") {
      setTimeout(() => {
        if (root && root.dataset.phase === phase) {
          root.style.display = "none";
        }
      }, 4500);
    }
    root.dataset.phase = phase;
  }

  function hide() {
    const root = document.getElementById(ROOT_ID);
    if (root) root.style.display = "none";
  }

  chrome.runtime.onMessage.addListener((msg) => {
    if (!msg || !msg.type) return;
    if (msg.type === "er_hud_update") update(msg);
    if (msg.type === "er_hud_hide") hide();
  });
})();
