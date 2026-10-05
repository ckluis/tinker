/* Tinker custom elements (MIT) — DataStar Rocket-style components.
 *
 * The server renders each component's initial HTML; the element upgrades it
 * client-side: signal bindings, event wiring from the data-events JSON the
 * server embedded, and the M2 SSE reactivity loop (rt-grid fetches its
 * query over POST /api/query and subscribes to id-only invalidations).
 *
 * Stability rule (PRD): public props, emitted events, documented signals,
 * CSS parts, and patch-target names are stable. Internal shadow-DOM
 * structure may change.
 */

function eventsOf(el) {
  try {
    return JSON.parse(el.getAttribute('data-events') || '[]');
  } catch {
    return [];
  }
}

// Minimal signal bus. The SSE transport feeds it; the API stays stable.
const TinkerSignals = {
  _map: new Map(),
  get(name) { return this._map.get(name); },
  set(name, value) {
    this._map.set(name, value);
    document.dispatchEvent(new CustomEvent('tinker:signal', { detail: { name, value } }));
  },
};
window.TinkerSignals = TinkerSignals;

class RtBase extends HTMLElement {
  connectedCallback() {
    this._events = eventsOf(this);
  }
  emit(name, detail) {
    const binding = this._events.find((e) => e.on === name);
    this.dispatchEvent(new CustomEvent(name, { detail, bubbles: true }));
    if (binding) {
      TinkerSignals.set('$lastEvent', { component: this.id, on: name, action: binding.action, args: binding.args });
    }
  }
}

class RtText extends RtBase {}
class RtStat extends RtBase {}

class RtSelect extends RtBase {
  connectedCallback() {
    super.connectedCallback();
    const sel = this.querySelector('select');
    if (sel) {
      sel.addEventListener('change', () => {
        TinkerSignals.set(`${this.id}.value`, sel.value);
        this.emit('change', { value: sel.value });
      });
    }
  }
}

class RtGrid extends RtBase {
  connectedCallback() {
    super.connectedCallback();
    this.addEventListener('click', (ev) => {
      const row = ev.target.closest('tr[data-row]');
      if (row) {
        TinkerSignals.set(`${this.id}.selectedRow`, row.getAttribute('data-row'));
        this.emit('rowSelect', { row: row.getAttribute('data-row') });
      }
    });
    // M2 governed reactivity loop: a `data-query` attribute (a QueryIntent)
    // turns the grid live. Initial rows come from POST /api/query; the
    // returned object_id subscribes this grid to id-only invalidations on
    // /api/sse. Patches are ordered by the server's per-org sequence.
    const intentRaw = this.querySelector('table')?.getAttribute('data-query');
    if (intentRaw) {
      try {
        this._intent = JSON.parse(intentRaw);
        this._lastSeq = 0;
        this._refresh();
      } catch {
        this._setError('bad query');
      }
    }
  }
  async _refresh() {
    const tbody = this.querySelector('table');
    TinkerSignals.set(`${this.id}.loading`, true);
    try {
      const res = await fetch('/api/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(this._intent),
      });
      if (!res.ok) throw new Error(`query ${res.status}`);
      const { rows, object_id } = await res.json();
      this._renderRows(rows || []);
      TinkerSignals.set(`${this.id}.rowCount`, (rows || []).length);
      TinkerSignals.set(`${this.id}.error`, null);
      this._subscribe(object_id);
    } catch (err) {
      this._setError(String(err && err.message || err));
    } finally {
      TinkerSignals.set(`${this.id}.loading`, false);
    }
  }
  _subscribe(object_id) {
    if (!object_id || this._sseObject === object_id) return;
    if (this._sse) this._sse.close();
    this._sseObject = object_id;
    const src = new EventSource(`/api/sse?object=${encodeURIComponent(object_id)}`);
    this._sse = src;
    src.addEventListener('invalidate', (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        // Ordered patches: ignore stale or duplicate invalidations.
        if (typeof msg.seq === 'number' && msg.seq > this._lastSeq) {
          this._lastSeq = msg.seq;
          this._refresh();
        }
      } catch { /* malformed event: next keep-alive resyncs */ }
    });
    // The server sends `resync` when this client lagged past the channel
    // buffer and may have missed invalidations: refetch unconditionally.
    src.addEventListener('resync', () => this._refresh());
    src.onerror = () => { /* EventSource reconnects on its own */ };
  }
  _renderRows(rows) {
    const tbody = this.querySelector('[data-patch-target="tbody"]');
    if (!tbody) return;
    let fields = [];
    try { fields = JSON.parse(tbody.getAttribute('data-fields') || '[]'); } catch {}
    const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="${Math.max(fields.length, 1)}">No rows</td></tr>`;
      return;
    }
    tbody.innerHTML = rows.map((r) => {
      const tds = fields.map((f) => `<td>${esc(r[f])}</td>`).join('');
      return `<tr data-row="${esc(r.__id || '')}">${tds}</tr>`;
    }).join('');
  }
  _setError(msg) {
    TinkerSignals.set(`${this.id}.error`, msg);
    const tbody = this.querySelector('[data-patch-target="tbody"]');
    if (tbody) tbody.innerHTML = `<tr><td>Error: ${msg}</td></tr>`;
  }
  // Patch target for M2's SSE loop.
  setRows(html) {
    const tbody = this.querySelector('[data-patch-target="tbody"]');
    if (tbody) tbody.innerHTML = html;
  }
  disconnectedCallback() {
    if (this._sse) this._sse.close();
  }
}

class RtForm extends RtBase {
  connectedCallback() {
    super.connectedCallback();
    const form = this.querySelector('form');
    if (form) {
      form.addEventListener('submit', (ev) => {
        const binding = this._events.find((e) => e.on === 'submit');
        if (binding && binding.action === 'submitForm') {
          // M2 wires this to a real endpoint; for M1 record the intent.
          ev.preventDefault();
          const values = Object.fromEntries(new FormData(form).entries());
          TinkerSignals.set(`${this.id}.values`, values);
          this.emit('submit', { values });
        }
      });
    }
  }
}

customElements.define('rt-text', RtText);
customElements.define('rt-stat', RtStat);
customElements.define('rt-select', RtSelect);
customElements.define('rt-grid', RtGrid);
customElements.define('rt-form', RtForm);

/* Sign-in (login page). Passkey: the WebAuthn assertion ceremony
 * (navigator.credentials.get) against a single-use server challenge.
 * SSO: the OIDC authorization-code flow (server-side PKCE + nonce).
 * The server decides everything; this only carries the ceremony.
 */
const b64url = {
  decode(s) {
    const b = atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '='));
    return Uint8Array.from(b, (c) => c.charCodeAt(0));
  },
  encode(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
};

function loginError(form, message) {
  let out = form.querySelector('.login-error');
  if (!out) {
    out = document.createElement('p');
    out.className = 'login-error';
    out.setAttribute('role', 'alert');
    form.append(out);
  }
  out.textContent = message;
}

document.getElementById('passkey-form')?.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const form = ev.currentTarget;
  const f = Object.fromEntries(new FormData(form));
  if (!window.PublicKeyCredential) {
    loginError(form, 'This browser does not support passkeys.');
    return;
  }
  try {
    const start = await fetch('/login/passkey/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ organization_id: f.organization_id, actor_id: f.actor_id }),
    }).then((r) => (r.ok ? r.json() : Promise.reject(new Error('start'))));
    const cred = await navigator.credentials.get({
      publicKey: {
        challenge: b64url.decode(start.challenge),
        rpId: start.rp_id,
        userVerification: 'preferred',
        timeout: 60000,
      },
    });
    const res = await fetch('/login/passkey/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        organization_id: f.organization_id,
        workspace_id: f.workspace_id,
        challenge_id: start.challenge_id,
        credential_id: b64url.encode(cred.rawId),
        client_data_json: b64url.encode(cred.response.clientDataJSON),
        authenticator_data: b64url.encode(cred.response.authenticatorData),
        signature: b64url.encode(cred.response.signature),
      }),
    });
    if (res.redirected || res.ok) {
      window.location.assign(res.url || '/apps');
    } else {
      loginError(form, 'Sign-in failed.');
    }
  } catch {
    loginError(form, 'Sign-in failed or was cancelled.');
  }
});

document.getElementById('oidc-form')?.addEventListener('submit', (ev) => {
  ev.preventDefault();
  const f = Object.fromEntries(new FormData(ev.currentTarget));
  const q = new URLSearchParams({ organization_id: f.organization_id, workspace_id: f.workspace_id });
  window.location.assign(`/login/oidc/start?${q}`);
});
