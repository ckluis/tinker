#!/usr/bin/env python3
"""Item 34 CDP driver: real-browser verification of the /schema builder page.

Drives headless Chromium (launched with --remote-debugging-port by the Rust
test) over the Chrome DevTools Protocol using only the Python standard
library -- no third-party websocket client available in this environment.

What it checks, in order:
  1. Unauthenticated GET /schema redirects to /login (auth gate).
  2. Builder view at 1440x900: renders, no JS console errors/warnings,
     no horizontal overflow, forms present, page contains no <script>.
  3. Builder view at 390x844: renders, no horizontal overflow.
  4. Full in-browser round trip as the builder: New draft -> add field ->
     mark canary -> promote to active, every step a real form submission,
     every redirect landing back on the builder.
  5. Member (no schema:evolve grant): viewer mode, no evolve controls.

Usage:
  browser_cdp.py <dbg_port> <base_url> <cookie_name> <builder_cookie>
                 <member_cookie> <object_id> <out_dir>

Writes screenshots + results.json into <out_dir>. Exit 0 only if every
assertion passes; failures go to stderr.
"""

import base64
import hashlib
import json
import os
import random
import socket
import sys
import time
import urllib.parse
import urllib.request


class CdpError(Exception):
    pass


class Ws:
    """Minimal RFC6455 client: text frames only, server->client unmasked."""

    def __init__(self, url):
        p = urllib.parse.urlparse(url)
        self.sock = socket.create_connection((p.hostname, p.port or 80), timeout=10)
        key = base64.b64encode(random.randbytes(16)).decode()
        target = p.path or "/"
        if p.query:
            target += "?" + p.query
        req = (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {p.hostname}:{p.port or 80}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise CdpError("websocket upgrade: connection closed")
            head += chunk
        status = head.split(b"\r\n", 1)[0]
        if b" 101 " not in status:
            raise CdpError(f"websocket upgrade failed: {status!r}")
        self.buf = b""
        self.id = 0
        self.events = []

    def _send_frame(self, opcode, payload: bytes):
        fin = 0x80 | opcode
        mask_key = random.randbytes(4)
        masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        hdr = bytes([fin, 0x80 | len(masked)]) if len(masked) < 126 else None
        if hdr is None:
            hdr = bytes([fin, 0x80 | 126]) + len(masked).to_bytes(2, "big")
        self.sock.sendall(hdr + mask_key + masked)

    def _fill(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise CdpError("websocket: connection closed")
            self.buf += chunk

    def _recv_frame(self, timeout):
        self.sock.settimeout(timeout)
        try:
            self._fill(2)
        except socket.timeout:
            return None, None
        b1, b2 = self.buf[0], self.buf[1]
        opcode = b1 & 0x0F
        ln = b2 & 0x7F
        off = 2
        if ln == 126:
            self._fill(4)
            ln = int.from_bytes(self.buf[2:4], "big")
            off = 4
        elif ln == 127:
            self._fill(10)
            ln = int.from_bytes(self.buf[2:10], "big")
            off = 10
        if b2 & 0x80:
            self._fill(off + 4)
            off += 4  # server must not mask; skip defensively
        self._fill(off + ln)
        payload = self.buf[off : off + ln]
        self.buf = self.buf[off + ln :]
        return opcode, payload

    def call(self, method, params=None, timeout=25):
        """Send a command; collect stray events while awaiting its response."""
        self.id += 1
        cid = self.id
        msg = {"id": cid, "method": method}
        if params is not None:
            msg["params"] = params
        self._send_frame(0x1, json.dumps(msg).encode())
        deadline = time.time() + timeout
        while True:
            opcode, payload = self._recv_frame(max(0.1, deadline - time.time()))
            if opcode is None:
                raise CdpError(f"CDP call {method} timed out")
            if opcode == 0x9:  # ping -> pong
                self._send_frame(0xA, payload)
                continue
            if opcode == 0x8:
                raise CdpError(f"CDP websocket closed during {method}")
            if opcode != 0x1:
                continue
            obj = json.loads(payload.decode())
            if obj.get("id") == cid:
                if "error" in obj:
                    raise CdpError(f"CDP {method} error: {obj['error']}")
                return obj.get("result", {})
            if "method" in obj:
                self.events.append(obj)

    def drain_events(self):
        evs, self.events = self.events, []
        return evs


def evaluate(ws, expr):
    r = ws.call(
        "Runtime.evaluate",
        {"expression": expr, "returnByValue": True, "awaitPromise": True},
    )
    res = r.get("result", {})
    if res.get("subtype") == "error" or "exceptionDetails" in r:
        raise CdpError(f"evaluate failed: {expr[:120]} -> {res}")
    return res.get("value")


def wait_load(ws, timeout=25):
    """Consume events until the next Page.loadEventFired."""
    deadline = time.time() + timeout
    for ev in ws.drain_events():
        if ev.get("method") == "Page.loadEventFired":
            return
    while time.time() < deadline:
        opcode, payload = ws._recv_frame(1.0)
        if opcode is None:
            continue
        if opcode == 0x9:
            ws._send_frame(0xA, payload)
            continue
        if opcode != 0x1:
            continue
        obj = json.loads(payload.decode())
        if obj.get("method") == "Page.loadEventFired":
            return
        if "method" in obj:
            ws.events.append(obj)
    raise CdpError("timed out waiting for Page.loadEventFired")


def navigate(ws, url):
    """Navigate via a page-created link click.

    This Chromium build (152) enforces Local Network Access checks and
    treats CDP-initiated navigations (Page.navigate, and even
    location.href assigned from Runtime.evaluate) as public-initiated,
    blocking them with ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS. A
    link created and clicked *by the page itself* carries the page's
    (local) initiator and is allowed. Chrome is therefore launched at a
    file:// bootstrap page (also local-initiated) which performs the
    very first hop; every hop after that goes through this helper.
    """
    ws.drain_events()
    escaped = url.replace("\\", "\\\\").replace("'", "\\'")
    evaluate(
        ws,
        "(() => { const a = document.createElement('a');"
        f" a.href = '{escaped}';"
        " document.body.appendChild(a); a.click(); })()",
    )
    wait_load(ws)


def set_viewport(ws, w, h):
    ws.call(
        "Emulation.setDeviceMetricsOverride",
        {
            "width": w,
            "height": h,
            "deviceScaleFactor": 1,
            "mobile": w < 768,
        },
    )


def screenshot(ws, path):
    r = ws.call("Page.captureScreenshot", {"format": "png"})
    with open(path, "wb") as f:
        f.write(base64.b64decode(r["data"]))


def set_cookie(ws, name, value):
    ws.call(
        "Network.setCookie",
        {
            "name": name,
            "value": value,
            "domain": "127.0.0.1",
            "path": "/",
            "httpOnly": True,
            "secure": False,
            "sameSite": "Lax",
        },
    )


def clear_cookies(ws):
    ws.call("Network.clearBrowserCookies")


def drain_and_classify(ws):
    """Drain pending CDP events; split into JS-console issues and
    informational Log-domain entries (network etc.). Single drain so
    nothing is lost between the two classifications."""
    errors, warnings, logs = [], [], []
    for ev in ws.drain_events():
        m = ev.get("method")
        if m == "Runtime.consoleAPICalled":
            t = ev["params"].get("type")
            args = " ".join(
                str(a.get("value", a.get("description", "")))
                for a in ev["params"].get("args", [])
            )
            if t == "error":
                errors.append(args)
            elif t == "warning":
                warnings.append(args)
        elif m == "Runtime.exceptionThrown":
            errors.append(str(ev["params"].get("exceptionDetails", {}))[:300])
        elif m == "Log.entryAdded":
            e = ev["params"]["entry"]
            logs.append(f"{e.get('level')}/{e.get('source')}: {e.get('text','')[:160]}")
    return errors, warnings, logs


def click_and_wait_load(ws, click_expr):
    """Click a submit button and wait for the resulting document load.

    Form actions on the builder 303-redirect back to the *same* builder
    URL, so waiting for a URL change would hang; wait for the next load
    event instead.
    """
    ws.drain_events()
    evaluate(ws, click_expr)
    wait_load(ws)
    return evaluate(ws, "location.href")


def check(name, cond, failures):
    print(("PASS " if cond else "FAIL ") + name, flush=True)
    if not cond:
        failures.append(name)


def main():
    (dbg_port, base, cookie_name, builder_cookie, member_cookie, object_id, outdir) = sys.argv[
        1:8
    ]
    os.makedirs(outdir, exist_ok=True)
    failures = []
    results = {"screenshots": {}, "checks": {}}

    with urllib.request.urlopen(f"http://127.0.0.1:{dbg_port}/json/list", timeout=10) as r:
        targets = json.load(r)
    pages = [t for t in targets if t.get("type") == "page"]
    if not pages:
        print("FAIL no page target from /json/list", file=sys.stderr)
        return 1
    ws = Ws(pages[0]["webSocketDebuggerUrl"])
    ws.call("Page.enable")
    ws.call("Runtime.enable")
    ws.call("Log.enable")
    ws.call("Network.enable")

    # --- 1. Unauthenticated -> login ---
    # Chrome was launched at the file:// bootstrap whose inline script
    # already hopped to base + "/schema" with no cookies set; the
    # server's 303 to /login is server-driven, so no CDP navigation was
    # needed for this first hop.
    url = evaluate(ws, "location.href")
    check("unauthenticated /schema redirects to /login", "/login" in url, failures)
    results["checks"]["unauth_redirect_url"] = url
    screenshot(ws, os.path.join(outdir, "schema_unauth_login_1440.png"))

    # --- 2. Builder, desktop 1440x900 ---
    set_viewport(ws, 1440, 900)
    clear_cookies(ws)
    set_cookie(ws, cookie_name, builder_cookie)
    ws.drain_events()
    navigate(ws, base + "/schema")
    errs, warns, logs = drain_and_classify(ws)
    results["checks"]["console_errors_builder_desktop"] = errs
    results["checks"]["console_warnings_builder_desktop"] = warns
    check("zero JS console errors on builder load (desktop)", errs == [], failures)
    check("zero JS console warnings on builder load (desktop)", warns == [], failures)
    results["checks"]["log_entries_builder_desktop"] = logs
    title = evaluate(ws, "document.title")
    check("builder page title", "Schema builder" in (title or ""), failures)
    mode = evaluate(ws, "document.querySelector('header .version').textContent")
    check("builder sees builder mode", (mode or "").strip() == "builder", failures)
    nscripts = evaluate(ws, "document.querySelectorAll('script').length")
    check("page ships no <script> (no-JS claim holds)", nscripts == 0, failures)
    results["checks"]["script_tags"] = nscripts
    overflow = evaluate(
        ws, "document.documentElement.scrollWidth > window.innerWidth"
    )
    check("no horizontal overflow at 1440px", not overflow, failures)
    results["checks"]["overflow_desktop"] = bool(overflow)
    forms = evaluate(
        ws,
        "[...document.querySelectorAll('form')].map(f => f.getAttribute('action'))",
    )
    results["checks"]["forms_builder_root"] = forms
    screenshot(ws, os.path.join(outdir, "schema_builder_desktop_1440.png"))

    # --- 3. Builder, mobile 390x844 ---
    set_viewport(ws, 390, 844)
    ws.drain_events()
    navigate(ws, evaluate(ws, "location.href"))
    errs, warns, _logs = drain_and_classify(ws)
    check("zero JS console errors on builder load (mobile)", errs == [], failures)
    check("zero JS console warnings on builder load (mobile)", warns == [], failures)
    overflow = evaluate(
        ws, "document.documentElement.scrollWidth > window.innerWidth"
    )
    check("no horizontal overflow at 390px", not overflow, failures)
    results["checks"]["overflow_mobile"] = bool(overflow)
    screenshot(ws, os.path.join(outdir, "schema_builder_mobile_390.png"))

    # --- 4. In-browser round trip: draft -> add field -> canary -> promote ---
    set_viewport(ws, 1440, 900)
    navigate(ws, f"{base}/schema?object={object_id}")
    has_draft = evaluate(
        ws, "document.querySelector('form[action$=\"/drafts\"] button') !== null"
    )
    check("New draft form present for builder", has_draft, failures)
    url = click_and_wait_load(
        ws, "document.querySelector('form[action$=\"/drafts\"] button').click()"
    )
    check("draft create lands back on builder", "/schema?object=" in url, failures)
    version_id = urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get("version", [None])[0]
    check("draft create redirect carries version id", bool(version_id), failures)
    results["checks"]["draft_version_id"] = version_id

    # Add field through the real form.
    fill = """
    (() => {
      const f = document.querySelector('form[action$="/fields"]');
      if (!f) return 'no-form';
      f.querySelector('input[name=name]').value = 'Nickname';
      f.querySelector('input[name=api_name]').value = 'nickname';
      f.querySelector('input[name=label]').value = 'Nickname';
      f.querySelector('select[name=field_type]').value = 'text';
      f.querySelector('button[type=submit]').click();
      return 'submitted';
    })()
    """
    present = evaluate(
        ws,
        "document.querySelector('form[action$=\"/fields\"]') !== null",
    )
    check("add-field form present on draft", present, failures)
    ws.drain_events()
    submitted = evaluate(ws, fill)
    check("add-field form submitted", submitted == "submitted", failures)
    wait_load(ws)
    url = evaluate(ws, "location.href")
    check("add-field lands back on builder", "/schema?object=" in url, failures)
    body = evaluate(ws, "document.body.innerText")
    check("added field 'nickname' listed", "nickname" in (body or ""), failures)

    # Mark canary, then promote.
    canary_btn = evaluate(
        ws, "document.querySelector('form[action$=\"/canary\"] button') !== null"
    )
    check("mark-canary form present on draft", canary_btn, failures)
    click_and_wait_load(
        ws, "document.querySelector('form[action$=\"/canary\"] button').click()"
    )
    body = evaluate(ws, "document.body.innerText")
    check("canary chip visible after mark-canary", "canary" in (body or ""), failures)

    promote_btn = evaluate(
        ws, "document.querySelector('form[action$=\"/promote\"] button') !== null"
    )
    check("promote form present on canary", promote_btn, failures)
    url = click_and_wait_load(
        ws, "document.querySelector('form[action$=\"/promote\"] button').click()"
    )
    check("promote lands back on builder", "/schema?object=" in url, failures)
    body = evaluate(ws, "document.body.innerText")
    check("active chip visible after promote", "active" in (body or ""), failures)
    errs, warns, _logs = drain_and_classify(ws)
    check("zero JS console errors across round trip", errs == [], failures)
    check("zero JS console warnings across round trip", warns == [], failures)
    results["checks"]["console_errors_roundtrip"] = errs
    results["checks"]["console_warnings_roundtrip"] = warns
    screenshot(ws, os.path.join(outdir, "schema_promoted_desktop_1440.png"))
    results["checks"]["promote_final_url"] = url
    results["version_id"] = version_id

    # --- 5. Member viewer: no evolve controls ---
    clear_cookies(ws)
    set_cookie(ws, cookie_name, member_cookie)
    navigate(ws, f"{base}/schema?object={object_id}")
    mode = evaluate(ws, "document.querySelector('header .version').textContent")
    check("member sees viewer mode", (mode or "").strip() == "viewer", failures)
    no_draft = evaluate(
        ws, "document.querySelector('form[action$=\"/drafts\"]') === null"
    )
    check("member sees no New-draft form", no_draft, failures)
    body = evaluate(ws, "document.body.innerText")
    check("member sees no 'Promote to active'", "Promote to active" not in (body or ""), failures)
    check("member sees no 'Add field'", "Add field" not in (body or ""), failures)
    check(
        "member still sees object data",
        "crm_contact" in (body or ""),
        failures,
    )
    overflow = evaluate(
        ws, "document.documentElement.scrollWidth > window.innerWidth"
    )
    check("no horizontal overflow for viewer at 1440px", not overflow, failures)
    screenshot(ws, os.path.join(outdir, "schema_viewer_desktop_1440.png"))

    results["failures"] = failures
    results["passed"] = not failures
    with open(os.path.join(outdir, "results.json"), "w") as f:
        json.dump(results, f, indent=2)
    print(f"RESULT passed={results['passed']} failures={len(failures)}", flush=True)
    return 0 if results["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CdpError as e:
        print(f"FAIL driver error: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:  # noqa: BLE001 - driver must fail loudly
        print(f"FAIL unexpected: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(3)
