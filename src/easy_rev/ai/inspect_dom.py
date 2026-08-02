"""DOM scrape + captcha / consent helpers for site.inspect v2."""

from __future__ import annotations

from typing import Any

# Captcha type sets (web RE detection only; solving is out of scope for easy-rev core)
SUPPORTED_CAPTCHA_TYPES = frozenset({
    "recaptcha_v2", "recaptcha_v3", "hcaptcha", "turnstile", "funcaptcha", "geetest",
})
UNSUPPORTED_CAPTCHA_TYPES = frozenset({
    "captchafox", "datadome", "perimeterx", "arkose_custom",
})



__all__ = [
    "DOM_SNAPSHOT_JS",
    "CONSENT_BUTTON_SELECTORS",
    "SUPPORTED_CAPTCHA_TYPES",
    "UNSUPPORTED_CAPTCHA_TYPES",
    "snapshot_page",
    "try_accept_consent",
    "try_click_next",
]

# Injected into the page via page.evaluate. Keep self-contained (no outer scope).
DOM_SNAPSHOT_JS = r"""() => {
  const cssEscape = (s) => {
    if (window.CSS && CSS.escape) return CSS.escape(s);
    return String(s).replace(/[^a-zA-Z0-9_-]/g, '\\$&');
  };

  const buttonSelector = (el) => {
    if (el.id) return '#' + cssEscape(el.id);
    const dt = el.getAttribute('data-test') || el.getAttribute('data-testid');
    if (dt) {
      const attr = el.getAttribute('data-test') ? 'data-test' : 'data-testid';
      return '[' + attr + '="' + String(dt).replace(/"/g, '\\"') + '"]';
    }
    const name = el.getAttribute('name');
    if (name) {
      return el.tagName.toLowerCase() + '[name="' + String(name).replace(/"/g, '\\"') + '"]';
    }
    if ((el.getAttribute('type') || '') === 'submit') {
      return 'button[type=submit], input[type=submit]';
    }
    const parts = (el.className && typeof el.className === 'string')
      ? el.className.trim().split(/\s+/).filter(Boolean).slice(0, 2).map(cssEscape)
      : [];
    if (parts.length) return el.tagName.toLowerCase() + '.' + parts.join('.');
    return null;
  };

  const inputSelector = (el) => {
    if (el.id) return '#' + cssEscape(el.id);
    const name = el.getAttribute('name');
    if (name) return el.tagName.toLowerCase() + '[name="' + String(name).replace(/"/g, '\\"') + '"]';
    const auto = el.getAttribute('autocomplete');
    if (auto) return el.tagName.toLowerCase() + '[autocomplete="' + auto + '"]';
    const dt = el.getAttribute('data-test') || el.getAttribute('data-testid');
    if (dt) {
      const attr = el.getAttribute('data-test') ? 'data-test' : 'data-testid';
      return '[' + attr + '="' + String(dt).replace(/"/g, '\\"') + '"]';
    }
    return null;
  };

  const inputs = [...document.querySelectorAll('input, textarea, select')].map((el) => ({
    tag: el.tagName.toLowerCase(),
    type: el.getAttribute('type') || '',
    name: el.getAttribute('name') || '',
    id: el.id || '',
    placeholder: el.getAttribute('placeholder') || '',
    autocomplete: el.getAttribute('autocomplete') || '',
    required: !!el.required,
    disabled: !!el.disabled,
    selector: inputSelector(el),
  }));

  const buttons = [...document.querySelectorAll('button, input[type=submit], [role=button]')].map((el) => ({
    text: (el.innerText || el.value || '').trim().slice(0, 80),
    type: el.getAttribute('type') || '',
    id: el.id || '',
    disabled: !!el.disabled,
    selector: buttonSelector(el),
  }));

  const forms = [...document.forms].map((f, i) => ({
    index: i,
    action: f.action || '',
    method: f.method || '',
    id: f.id || '',
  }));

  // Captcha / challenge widgets
  const captchas = [];
  const pushCaptcha = (type, siteKey, vendor, el) => {
    captchas.push({
      type,
      site_key: siteKey || null,
      vendor: vendor || type,
      selector: el && el.id ? '#' + cssEscape(el.id) : null,
    });
  };

  for (const el of document.querySelectorAll('.g-recaptcha, [data-sitekey]')) {
    const key = el.getAttribute('data-sitekey') || '';
    const cls = (el.className || '').toString().toLowerCase();
    if (cls.includes('h-captcha') || el.classList.contains('h-captcha')) {
      pushCaptcha('hcaptcha', key, 'hcaptcha', el);
    } else if (cls.includes('cf-turnstile') || el.classList.contains('cf-turnstile')) {
      pushCaptcha('turnstile', key, 'cloudflare', el);
    } else if (key || cls.includes('g-recaptcha')) {
      pushCaptcha('recaptcha', key, 'google', el);
    }
  }
  for (const el of document.querySelectorAll('.h-captcha, [data-hcaptcha-widget-id]')) {
    pushCaptcha('hcaptcha', el.getAttribute('data-sitekey') || '', 'hcaptcha', el);
  }
  for (const el of document.querySelectorAll('.cf-turnstile, [data-turnstile-widget-id]')) {
    pushCaptcha('turnstile', el.getAttribute('data-sitekey') || '', 'cloudflare', el);
  }

  const html = document.documentElement.outerHTML || '';
  const scripts = [...document.querySelectorAll('script[src]')].map((s) => s.getAttribute('src') || '');
  const iframes = [...document.querySelectorAll('iframe[src]')].map((f) => f.getAttribute('src') || '');
  const blob = (html + ' ' + scripts.join(' ') + ' ' + iframes.join(' ')).toLowerCase();
  if (
    blob.includes('captchafox') ||
    blob.includes('captcha.fox') ||
    document.querySelector('[class*="captchafox"], [id*="captchafox"], iframe[src*="captchafox"]')
  ) {
    pushCaptcha('captchafox', null, 'captchafox', null);
  }
  if (blob.includes('funcaptcha') || blob.includes('arkoselabs')) {
    pushCaptcha('funcaptcha', null, 'arkoselabs', null);
  }
  if (blob.includes('geetest')) {
    pushCaptcha('geetest', null, 'geetest', null);
  }

  // Visible validation / alert-ish text
  const page_errors = [];
  const seen = new Set();
  const pushErr = (t) => {
    const s = (t || '').replace(/\s+/g, ' ').trim();
    if (!s || s.length < 3 || s.length > 200) return;
    const k = s.toLowerCase();
    if (seen.has(k)) return;
    seen.add(k);
    page_errors.push(s);
  };
  for (const sel of [
    '[role="alert"]',
    '.error',
    '.invalid-feedback',
    '.pos-form-message',
    '.onereg-hint-block',
    '[class*="error-message"]',
    '[data-test*="error"]',
  ]) {
    try {
      for (const el of document.querySelectorAll(sel)) {
        if (el.offsetParent === null && getComputedStyle(el).display === 'none') continue;
        pushErr(el.innerText || el.textContent);
      }
    } catch (e) {}
  }

  const bodyText = (document.body && document.body.innerText) || '';
  const visible_text = bodyText.replace(/\s+/g, ' ').trim().slice(0, 1500);

  // Heuristic primary CTA candidates
  const next_candidates = buttons
    .filter((b) => !b.disabled)
    .filter((b) => {
      const t = (b.text || '').toLowerCase();
      return (
        /\b(next|continue|submit|sign up|signup|register|create|agree|accept|proceed|start)\b/i.test(t) ||
        (b.type || '').toLowerCase() === 'submit'
      );
    })
    .slice(0, 8);

  return {
    title: document.title,
    url: location.href,
    forms,
    inputs,
    buttons,
    captchas,
    page_errors: page_errors.slice(0, 12),
    visible_text,
    next_candidates,
    html_snippet: html.slice(0, 8000),
  };
}"""


CONSENT_BUTTON_SELECTORS = (
    # Common CMP / privacy gates
    "button:has-text('Accept')",
    "button:has-text('Accept all')",
    "button:has-text('I agree')",
    "button:has-text('Agree')",
    "button:has-text('Allow all')",
    "button:has-text('Got it')",
    "button:has-text('OK')",
    "button:has-text('Continue')",
    "button:has-text('Continue to Mail.com')",
    "[id*='accept' i]",
    "[class*='accept' i]",
    "[data-testid*='accept' i]",
    "[data-test*='accept' i]",
)


async def try_accept_consent(page: Any, *, timeout_ms: int = 2500) -> list[str]:
    """Best-effort click through cookie / privacy consent layers. Returns clicked selectors."""
    clicked: list[str] = []
    for sel in CONSENT_BUTTON_SELECTORS:
        try:
            # Playwright supports :has-text; mock engine may not — ignore failures.
            locator_click = getattr(page, "click", None)
            if locator_click is None:
                continue
            await page.click(sel, timeout=timeout_ms)
            clicked.append(sel)
            # one successful consent click is usually enough
            break
        except Exception:  # noqa: BLE001
            continue
    # Fallback: JS text match for engines without :has-text
    if not clicked:
        try:
            sel = await page.evaluate(
                """() => {
                  const texts = [
                    'accept all', 'accept', 'i agree', 'agree', 'allow all',
                    'continue to mail.com', 'continue', 'got it', 'ok'
                  ];
                  const nodes = [...document.querySelectorAll(
                    'button, a, [role=button], input[type=button], input[type=submit]')];
                  for (const el of nodes) {
                    const t = (el.innerText || el.value || '').trim().toLowerCase();
                    if (!t) continue;
                    if (texts.some((x) => t === x || t.includes(x))) {
                      if (el.id) return '#' + el.id;
                      el.setAttribute('data-easy-rev-consent', '1');
                      return '[data-easy-rev-consent="1"]';
                    }
                  }
                  return null;
                }"""
            )
            if sel:
                await page.click(sel, timeout=timeout_ms)
                clicked.append(str(sel))
        except Exception:  # noqa: BLE001
            pass
    return clicked


async def snapshot_page(page: Any) -> dict[str, Any]:
    data = await page.evaluate(DOM_SNAPSHOT_JS)
    if not isinstance(data, dict):
        return {"title": None, "url": getattr(page, "url", None), "inputs": [], "buttons": []}
    return data


async def try_click_next(page: Any, *, timeout_ms: int = 3000) -> str | None:
    """Click a likely Next/Continue/Submit button that is enabled."""
    snap = await snapshot_page(page)
    for cand in snap.get("next_candidates") or []:
        sel = cand.get("selector")
        if not sel:
            continue
        try:
            await page.click(str(sel), timeout=timeout_ms)
            return str(sel)
        except Exception:  # noqa: BLE001
            continue
    # text fallback via JS mark
    try:
        sel = await page.evaluate(
            """() => {
              const re = /\\b(next|continue|submit|sign up|register|create account|agree)\\b/i;
              const nodes = [...document.querySelectorAll('button, input[type=submit], [role=button]')];
              for (const el of nodes) {
                if (el.disabled) continue;
                const t = (el.innerText || el.value || '').trim();
                if (!re.test(t)) continue;
                el.setAttribute('data-easy-rev-next', '1');
                return '[data-easy-rev-next="1"]';
              }
              return null;
            }"""
        )
        if sel:
            await page.click(str(sel), timeout=timeout_ms)
            return str(sel)
    except Exception:  # noqa: BLE001
        return None
    return None


