'use strict';

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const SVG_NS = 'http://www.w3.org/2000/svg';

/** Baut DOM ohne innerHTML – Nutzerdaten landen ausschließlich als Text im Dokument. */
function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k === 'value') el.value = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k in el && typeof v !== 'string') el[k] = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function svgEl(tag, attrs = {}, ...kids) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  el.append(...kids);
  return el;
}

function icon(name, cls = '') {
  return svgEl('svg', { class: `i ${cls}`.trim(), 'aria-hidden': 'true' }, svgEl('use', { href: `#i-${name}` }));
}

function setIcon(svg, name) { svg.firstChild.setAttribute('href', `#i-${name}`); }

function iconBtn(name, title, onclick, cls = '') {
  return h('button', { type: 'button', class: `icon-btn ${cls}`.trim(), title, 'aria-label': title, onclick }, icon(name));
}

// ---------- Einstellungen (nur Komfort, keine Geheimnisse) ----------

const DEFAULT_SETTINGS = {
  autoLockMin: 5,
  clipClearSec: 30,
  lockOnMinimize: false,
  contentProtected: true,
  gen: { length: 20, lower: true, upper: true, digits: true, symbols: true, avoidAmbiguous: false },
};

function loadSettings() {
  try {
    const raw = JSON.parse(localStorage.getItem('ragnavault.settings') || '{}');
    return { ...DEFAULT_SETTINGS, ...raw, gen: { ...DEFAULT_SETTINGS.gen, ...(raw.gen || {}) } };
  } catch {
    return structuredClone(DEFAULT_SETTINGS);
  }
}
function saveSettings() {
  try { localStorage.setItem('ragnavault.settings', JSON.stringify(settings)); } catch { /* egal */ }
}

const settings = loadSettings();

// ---------- Zustand ----------

const KIND = {
  login: { label: 'Login', icon: 'key', new: 'Neuer Login' },
  totp: { label: '2FA-Code', icon: 'timer', new: 'Neuer 2FA-Code' },
  note: { label: 'Sichere Notiz', icon: 'note', new: 'Neue Notiz' },
};
const FILTERS = [
  { key: 'all', label: 'Alle Einträge', icon: 'grid' },
  { key: 'favorites', label: 'Favoriten', icon: 'star' },
  { key: 'login', label: 'Logins', icon: 'key' },
  { key: 'totp', label: '2FA-Codes', icon: 'timer' },
  { key: 'note', label: 'Notizen', icon: 'note' },
  { key: 'security', label: 'Sicherheit', icon: 'shield' },
];
const STRENGTH_LABEL = ['Sehr schwach', 'Schwach', 'Mittel', 'Stark', 'Sehr stark'];
const YEAR = 365 * 24 * 3600;
const REVEAL_MS = 20_000;

const state = {
  entries: [],
  filter: 'all',
  query: '',
  selectedId: null,
  editing: null,       // Entwurf im Editor
  editingOrig: '',     // Ausgangszustand für „ungespeicherte Änderungen“
  revealed: null,      // { id, key, value } – höchstens ein sichtbares Geheimnis
  revealTimer: null,
  notes: null,         // { id, value } – Notizen des gewählten Eintrags
  codes: new Map(),
  lastActivity: Date.now(),
  unlocked: false,
  clipUntil: 0,
};

// ---------- Hilfen ----------

let toastTimer;
function toast(msg, kind = 'check') {
  const t = $('#toast');
  const isErr = kind === 'err';
  t.replaceChildren(icon(isErr ? 'alert' : kind), h('span', { text: msg }));
  t.classList.toggle('err', isErr);
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, isErr ? 4500 : 2000);
}

function errText(e) { return typeof e === 'string' ? e : (e?.message || String(e)); }

async function busy(button, label, fn) {
  const old = [...button.childNodes];
  button.disabled = true;
  button.textContent = label;
  try { return await fn(); } finally { button.disabled = false; button.replaceChildren(...old); }
}

function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

function formatCode(code) {
  if (!code) return '––– –––';
  const cut = code.length === 8 ? 4 : 3;
  return `${code.slice(0, cut)} ${code.slice(cut)}`;
}

function initial(title) { return ([...title.trim()][0] || '?').toUpperCase(); }

function hue(s) {
  let x = 7;
  for (const ch of s.toLowerCase()) x = (x * 31 + ch.codePointAt(0)) >>> 0;
  return x % 360;
}

function avatar(e, big = false) {
  const el = h('div', { class: `avatar${big ? ' big' : ''}` });
  el.style.setProperty('--h', String(hue(e.title || e.kind)));
  if (e.kind === 'login') el.textContent = initial(e.title || '?');
  else el.append(icon(KIND[e.kind].icon));
  return el;
}

function hostOf(url) {
  try { return new URL(url.includes('://') ? url : `https://${url}`).host; } catch { return url; }
}

function safeHref(url) {
  if (!url) return null;
  try {
    const u = new URL(url.includes('://') ? url : `https://${url}`);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : null;
  } catch { return null; }
}

function colorize(pw) {
  const frag = document.createDocumentFragment();
  for (const ch of pw) {
    if (/[0-9]/.test(ch)) frag.append(h('span', { class: 'd', text: ch }));
    else if (/[^\p{L}]/u.test(ch)) frag.append(h('span', { class: 's', text: ch }));
    else frag.append(ch);
  }
  return frag;
}

const MASK = '•'.repeat(12);

function fmtDate(ts) {
  return new Date(ts * 1000).toLocaleDateString('de-DE', { day: '2-digit', month: 'short', year: 'numeric' });
}

function relTime(ts) {
  const diff = ts - Date.now() / 1000;
  const rtf = new Intl.RelativeTimeFormat('de', { numeric: 'auto' });
  const steps = [[60, 'second'], [3600, 'minute'], [86400, 'hour'], [2592000, 'day'], [31536000, 'month'], [Infinity, 'year']];
  const div = { second: 1, minute: 60, hour: 3600, day: 86400, month: 2592000, year: 31536000 };
  for (const [limit, unit] of steps) {
    if (Math.abs(diff) < limit) return rtf.format(Math.round(diff / div[unit]), unit);
  }
  return '';
}

/** Gleiche Schwellen wie im Rust-Backend (strength.rs). */
function scoreFromBits(b) { return b < 28 ? 0 : b < 40 ? 1 : b < 60 ? 2 : b < 80 ? 3 : 4; }

function setMeter(el, score) { el.dataset.score = score == null ? 'empty' : String(score); }

function confirmDialog(title, text, yesLabel) {
  const dlg = $('#dlg-confirm');
  $('#confirm-title').textContent = title;
  $('#confirm-text').textContent = text;
  $('#confirm-yes').textContent = yesLabel;
  dlg.returnValue = '';
  dlg.showModal();
  return new Promise((resolve) => {
    dlg.addEventListener('close', () => resolve(dlg.returnValue === 'yes'), { once: true });
  });
}

function isTyping() {
  const a = document.activeElement;
  return a && (a.matches('input, textarea, select') || a.isContentEditable);
}

// ---------- Sicherheitsbewertung ----------

const issues = {
  weak: (e) => e.hasPassword && e.strength != null && e.strength <= 1,
  reused: (e) => e.reused,
  old: (e) => e.hasPassword && e.passwordChangedAt > 0 && Date.now() / 1000 - e.passwordChangedAt > YEAR,
  noTotp: (e) => e.kind === 'login' && e.hasPassword && !e.totp,
};
const hasIssue = (e) => issues.weak(e) || issues.reused(e) || issues.old(e);

// ---------- Zwischenablage ----------

async function copyField(id, field, label, btn = null, index = null) {
  try {
    await invoke('copy_field', { id, field, index, clearAfter: settings.clipClearSec });
    copied(label, btn);
  } catch (e) { toast(errText(e), 'err'); }
}

function copied(label, btn) {
  toast(`${label} kopiert`);
  if (btn) {
    const svg = $('svg', btn);
    const orig = svg.firstChild.getAttribute('href');
    setIcon(svg, 'check');
    btn.classList.add('done');
    setTimeout(() => { svg.firstChild.setAttribute('href', orig); btn.classList.remove('done'); }, 1200);
  }
  if (settings.clipClearSec > 0) {
    state.clipUntil = Date.now() + settings.clipClearSec * 1000;
    updateClipPill();
  }
}

function updateClipPill() {
  const left = Math.ceil((state.clipUntil - Date.now()) / 1000);
  $('#clip-pill').hidden = left <= 0;
  if (left > 0) $('#clip-secs').textContent = left;
}

$('#clip-clear').addEventListener('click', async () => {
  try { await invoke('clear_clipboard'); } catch (e) { toast(errText(e), 'err'); return; }
  state.clipUntil = 0;
  updateClipPill();
  toast('Zwischenablage geleert');
});

// ---------- Geheimnisse anzeigen ----------

function isRevealed(id, key) { return state.revealed?.id === id && state.revealed.key === key; }

function hideRevealed() {
  clearTimeout(state.revealTimer);
  state.revealed = null;
}

async function toggleReveal(id, field, index = null) {
  const key = index == null ? field : `${field}:${index}`;
  if (isRevealed(id, key)) { hideRevealed(); renderDetail(); return; }
  try {
    const value = await invoke('reveal_field', { id, field, index });
    hideRevealed();
    state.revealed = { id, key, value };
    // Sichtbare Geheimnisse verschwinden nach kurzer Zeit wieder von selbst.
    state.revealTimer = setTimeout(() => { state.revealed = null; renderDetail(); }, REVEAL_MS);
    renderDetail();
  } catch (e) { toast(errText(e), 'err'); }
}

// ---------- Bildschirme ----------

function show(screen) {
  for (const name of ['setup', 'unlock', 'main']) $(`#screen-${name}`).hidden = name !== screen;
  const focus = { setup: '#setup-pw', unlock: '#unlock-pw', main: '#search' }[screen];
  requestAnimationFrame(() => $(focus)?.focus());
}

async function applyWindowSettings() {
  try { await invoke('set_content_protected', { enabled: settings.contentProtected }); } catch { /* nicht kritisch */ }
  try { await invoke('set_lock_on_minimize', { enabled: settings.lockOnMinimize }); } catch { /* nicht kritisch */ }
}

let gate = { vaultCount: 0, vaultName: null };

/** Liest den aktuellen Tresor und aktualisiert Namen, Pfad und den Eck-Knopf. */
async function refreshStatus() {
  const st = await invoke('status');
  gate = st;
  $('#vault-path').textContent = st.path;
  $('#unlock-vault-name').textContent = st.vaultName || 'Tresor';
  $('#sidebar-vault-name').textContent = st.vaultCount > 1 ? st.vaultName : '';
  $('#vault-corner').textContent = st.vaultCount >= 2 ? 'Tresore verwalten' : 'Neuen Tresor anlegen';
  return st;
}

async function init() {
  applyWindowSettings();
  const st = await refreshStatus();
  if (st.unlocked) await enterVault();
  else if (st.exists) show('unlock');
  else openSetup();
  await ensureLicense();
}

function openSetup() {
  const another = gate.vaultCount > 0;
  $('#setup-form').reset();
  $('#setup-name').value = another ? '' : 'Mein Tresor';
  $('#setup-title').textContent = another ? 'Neuen Tresor anlegen' : 'Master-Passwort festlegen';
  $('#setup-back').hidden = !another;
  $('#setup-error').textContent = '';
  setMeter($('#setup-meter'), null);
  for (const id of ['req-len', 'req-strength']) $(`#${id}`).classList.remove('ok');
  show('setup');
  if (another) requestAnimationFrame(() => $('#setup-name').focus());
}

$('#setup-back').addEventListener('click', () => show('unlock'));
$('#vault-corner').addEventListener('click', () => (gate.vaultCount >= 2 ? openVaultManager() : openSetup()));

// ---------- Tresore verwalten ----------

async function openVaultManager() {
  $('#vaults-error').textContent = '';
  await renderVaultList();
  $('#dlg-vaults').showModal();
}

async function renderVaultList() {
  const vaults = await invoke('list_vaults');
  $('#vault-list').replaceChildren(...vaults.map((v) => {
    const title = h('div', { class: 'vault-title' }, h('b', { text: v.name }), v.current ? h('span', { class: 'chip ok', text: 'Aktuell' }) : null);
    const row = h('li', { class: `vault-row${v.current ? ' current' : ''}` },
      h('div', { class: 'vault-icon' }, icon('lock')),
      h('div', { class: 'grow' }, title,
        h('div', { class: 'hint', text: v.exists ? `Angelegt am ${fmtDate(v.createdAt)}` : 'Datei nicht gefunden' })),
      iconBtn('pencil', 'Umbenennen', () => startRename(title, v)),
      iconBtn('x', 'Aus der Liste entfernen (Datei bleibt erhalten)', () => forgetVault(v)),
      h('button', { type: 'button', class: 'btn', disabled: !v.exists, onclick: () => chooseVault(v) }, 'Öffnen'));
    return row;
  }));
}

function startRename(title, v) {
  const input = h('input', { class: 'rename-input', value: v.name, maxlength: 40, spellcheck: 'false' });
  const save = async () => {
    try {
      await invoke('rename_vault', { id: v.id, name: input.value });
      await refreshStatus();
      await renderVaultList();
    } catch (e) { $('#vaults-error').textContent = errText(e); input.focus(); }
  };
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); save(); }
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); renderVaultList(); }
  });
  input.addEventListener('blur', () => { if (input.isConnected) save(); });
  title.replaceChildren(input);
  input.select();
}

async function chooseVault(v) {
  try {
    await invoke('select_vault', { id: v.id });
    $('#dlg-vaults').close();
    await refreshStatus();
    $('#unlock-error').textContent = '';
    $('#unlock-pw').value = '';
    show('unlock');
  } catch (e) { $('#vaults-error').textContent = errText(e); }
}

async function forgetVault(v) {
  const ok = await confirmDialog('Aus der Liste entfernen?',
    `„${v.name}“ verschwindet aus der Liste. Die Tresor-Datei selbst bleibt auf der Festplatte erhalten.`, 'Entfernen');
  if (!ok) return;
  try {
    await invoke('forget_vault', { id: v.id });
    const st = await refreshStatus();
    if (!st.vaultCount) { $('#dlg-vaults').close(); openSetup(); return; }
    await renderVaultList();
  } catch (e) { $('#vaults-error').textContent = errText(e); }
}

$('#vaults-close').addEventListener('click', () => $('#dlg-vaults').close());
$('#vaults-new').addEventListener('click', () => { $('#dlg-vaults').close(); openSetup(); });

// ---------- Lizenz ----------

function fillAbout(info) {
  $('#about-version').textContent = info.version;
  $('#about-license').textContent = info.licenseAcceptedAt
    ? `RagnaSoftware Generallizenz ${info.licenseVersion} – zugestimmt am ${fmtDate(info.licenseAcceptedAt)}`
    : `RagnaSoftware Generallizenz ${info.licenseVersion}`;
  $('#lic-meta').textContent = `Version ${info.licenseVersion}, gültig ab ${info.licenseDate}`;
}

/** Erster Start (oder neue Lizenzversion): Ohne Zustimmung geht es nicht weiter. */
async function ensureLicense() {
  const info = await invoke('app_info');
  fillAbout(info);
  if (info.licenseAccepted) return;
  const dlg = $('#dlg-license');
  dlg.showModal();
  await new Promise((resolve) => {
    $('#license-accept').onclick = async () => {
      try {
        await invoke('accept_license');
        fillAbout(await invoke('app_info'));
        await licenseToGate(dlg);
        resolve();
      } catch (e) { toast(errText(e), 'err'); }
    };
  });
  $('#screen-setup:not([hidden]) #setup-pw, #screen-unlock:not([hidden]) #unlock-pw')?.focus();
}

// ---------- Übergang Lizenz → Passwort-Karte ----------

const px = (r, extra = {}) => ({ left: `${r.left}px`, top: `${r.top}px`, width: `${r.width}px`, height: `${r.height}px`, ...extra });
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const box = (cx, cy, size) => ({ left: cx - size / 2, top: cy - size / 2, width: size, height: size });

/**
 * Die Lizenzkarte löst sich auf, schrumpft zur „Tresortür“ um das Logo, das sich wie ein Schlüssel
 * dreht und eine Schockwelle mit Funken auslöst. Danach weitet sich die Tür exakt zur
 * Passwort-Karte, das Logo fliegt in den Schriftzug und der Inhalt baut sich gestaffelt auf.
 */
async function licenseToGate(dlg) {
  const target = $('.gate:not([hidden]) .gate-card');
  if (!target || !dlg.animate || matchMedia('(prefers-reduced-motion: reduce)').matches) { dlg.close(); return; }

  // 1) Inhalt der Lizenzkarte löst sich nach oben auf
  const body = $('.dialog-body', dlg);
  await Promise.all([...body.children].map((el, i) => el.animate(
    [{ opacity: 1, transform: 'none', filter: 'blur(0)' }, { opacity: 0, transform: 'translateY(-16px) scale(.96)', filter: 'blur(6px)' }],
    { duration: 300, delay: i * 32, easing: 'cubic-bezier(.5,0,.75,0)', fill: 'forwards' }).finished));

  const from = dlg.getBoundingClientRect();
  const to = target.getBoundingClientRect();
  const wm = $('.wordmark', target).getBoundingClientRect();
  const cx = from.left + from.width / 2;
  const cy = from.top + from.height / 2;
  const ICON = 116;

  const layer = h('div', { class: 'fx-layer' });
  const backdrop = h('div', { class: 'fx-backdrop' });
  const card = h('div', { class: 'fx-card' });
  const dial = h('div', { class: 'fx-dial' });
  const flyer = h('div', { class: 'fx-flyer' }, h('img', { src: 'logo-icon.png', alt: '' }));
  const rings = [0, 1, 2].map(() => h('div', { class: 'fx-ring' }));
  const sparks = Array.from({ length: 40 }, () => h('i', { class: 'fx-spark' }));
  Object.assign(card.style, px(from));
  Object.assign(dial.style, px(box(cx, cy, 232)));
  Object.assign(flyer.style, px(box(cx, cy, ICON)));
  for (const r of rings) Object.assign(r.style, px(box(cx, cy, 170)));
  for (const s of sparks) Object.assign(s.style, { left: `${cx}px`, top: `${cy}px` });
  layer.append(backdrop, card, dial, ...rings, ...sparks, flyer);

  // Nahtloser Wechsel: Dialog weg, identisch aussehende Karte an seiner Stelle
  target.classList.add('fx-hidden');
  document.body.append(layer);
  dlg.close();

  const T_TURN = 760; // Moment, in dem der „Schlüssel“ umdreht
  const swing = 'cubic-bezier(.75,0,.25,1)';

  backdrop.animate([{ opacity: 1 }, { opacity: 1, offset: 0.5 }, { opacity: 0 }], { duration: 1600, fill: 'forwards' });

  // 2) Karte → Tresortür → Passwort-Karte
  card.animate([
    px(from, { borderRadius: '18px', easing: swing }),
    px(box(cx, cy, 176), { borderRadius: '46px', offset: 0.36 }),
    px(box(cx, cy, 176), { borderRadius: '46px', offset: 0.54, easing: swing }),
    px(to, { borderRadius: '20px' }),
  ], { duration: 1560, fill: 'forwards' });

  // 3) Logo taucht auf, rastet ein, dreht wie ein Schlüssel und leuchtet auf
  const glow = (b, r, a) => `brightness(${b}) drop-shadow(0 0 ${r}px rgba(56,189,248,${a}))`;
  $('img', flyer).animate([
    { opacity: 0, transform: 'scale(.25) rotate(-140deg)', filter: glow(1, 0, 0), easing: 'cubic-bezier(.2,.9,.3,1.25)' },
    { opacity: 1, transform: 'scale(1) rotate(0deg)', filter: glow(1.1, 16, 0.5), offset: 0.4, easing: 'ease-in-out' },
    { opacity: 1, transform: 'scale(.9) rotate(-12deg)', filter: glow(1, 10, 0.4), offset: 0.52, easing: 'cubic-bezier(.3,1.4,.5,1)' },
    { opacity: 1, transform: 'scale(1.16) rotate(360deg)', filter: glow(1.9, 44, 0.95), offset: 0.68, easing: 'ease-out' },
    { opacity: 1, transform: 'scale(1) rotate(360deg)', filter: glow(1, 8, 0.25) },
  ], { duration: 1150, fill: 'forwards' });

  // Rotierender Ring um das Schloss wie ein Zahlenrad
  dial.animate([
    { opacity: 0, transform: 'scale(.55) rotate(0deg)', easing: 'ease-out' },
    { opacity: 1, transform: 'scale(1) rotate(220deg)', offset: 0.55, easing: 'cubic-bezier(.6,0,.4,1)' },
    { opacity: 0, transform: 'scale(1.7) rotate(480deg)' },
  ], { duration: 1150, delay: 120, fill: 'forwards' });

  // 4) Schockwellen und Funkenflug beim Umdrehen
  rings.forEach((r, i) => r.animate(
    [{ opacity: 0.95, transform: 'scale(.45)' }, { opacity: 0, transform: 'scale(4.4)' }],
    { duration: 1050, delay: T_TURN + i * 120, easing: 'cubic-bezier(.1,.6,.3,1)', fill: 'forwards' }));
  sparks.forEach((s, i) => {
    const angle = (i / sparks.length) * Math.PI * 2 + Math.random() * 0.3;
    const dist = 130 + Math.random() * 260;
    const size = 3 + Math.random() * 6;
    Object.assign(s.style, { width: `${size}px`, height: `${size}px`, margin: `${-size / 2}px 0 0 ${-size / 2}px` });
    s.animate([
      { opacity: 1, transform: 'translate(0,0) scale(1)' },
      { opacity: 0, transform: `translate(${Math.cos(angle) * dist}px, ${Math.sin(angle) * dist}px) scale(.2)` },
    ], { duration: 650 + Math.random() * 650, delay: T_TURN + Math.random() * 90, easing: 'cubic-bezier(.05,.7,.3,1)', fill: 'forwards' });
  });

  // 5) Logo fliegt an seinen Platz im Schriftzug der Passwort-Karte
  // Das Icon sitzt links im Schriftzug und ist etwa so breit wie dieser hoch ist.
  const landed = `translate(${wm.left + wm.height * 0.46 - cx}px, ${wm.top + wm.height / 2 - cy}px) scale(${wm.height / ICON})`;
  flyer.animate([
    { transform: 'translate(0,0) scale(1)', opacity: 1 },
    { transform: landed, opacity: 1, offset: 0.85 },
    { transform: landed, opacity: 0 },
  ], { duration: 700, delay: 1000, easing: 'cubic-bezier(.65,0,.25,1)', fill: 'forwards' });

  // 6) Die echte Karte übernimmt, Inhalt baut sich gestaffelt auf
  await wait(1540);
  target.classList.remove('fx-hidden');
  const parts = [$('.gate-brand', target), ...$('form', target).children];
  parts.forEach((el, i) => el.animate(
    [{ opacity: 0, transform: 'translateY(12px)', filter: 'blur(4px)' }, { opacity: 1, transform: 'none', filter: 'blur(0)' }],
    { duration: 460, delay: 60 + i * 45, easing: 'cubic-bezier(.2,.8,.2,1)', fill: 'backwards' }));
  card.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 240, fill: 'forwards' });
  await wait(260);
  layer.remove();
}

$('#dlg-license').addEventListener('cancel', (e) => e.preventDefault());
$('#license-ack').addEventListener('change', (e) => { $('#license-accept').disabled = !e.target.checked; });
$('#license-decline').addEventListener('click', () => invoke('quit'));

// Links öffnen im Standardbrowser (über Rust, nur http/https) statt im App-Fenster.
document.addEventListener('click', (e) => {
  const a = e.target.closest('a[href]');
  if (!a) return;
  e.preventDefault();
  invoke('open_url', { url: a.href }).catch((err) => toast(errText(err), 'err'));
});

async function enterVault() {
  state.unlocked = true;
  state.lastActivity = Date.now();
  updateAutolockHint();
  await reloadEntries();
  show('main');
  refreshCodes();
}

async function lockVault(reason = '') {
  if (!state.unlocked) return;
  state.unlocked = false;
  try { await invoke('lock'); } catch { /* Sitzung ist ohnehin weg */ }
  hideRevealed();
  Object.assign(state, { entries: [], selectedId: null, editing: null, editingOrig: '', notes: null });
  state.codes.clear();
  $('#entries').replaceChildren();
  $('#detail').replaceChildren();
  $('#search').value = state.query = '';
  for (const d of $$('dialog[open]')) d.close();
  $('#unlock-pw').value = '';
  $('#unlock-error').textContent = '';
  await refreshStatus();
  show('unlock');
  if (reason) toast(reason, 'lock');
}

listen('vault-locked', () => {
  // Rust hat bereits gesperrt (Minimieren) – Oberfläche nachziehen.
  if (state.unlocked) lockVault('Beim Minimieren gesperrt');
});

// Passwortfelder auf den Sperrbildschirmen: Anzeigen-Schalter und Feststelltasten-Warnung
for (const btn of $$('[data-reveal]')) {
  btn.append(icon('eye'));
  btn.addEventListener('click', () => {
    const input = document.getElementById(btn.dataset.reveal);
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    setIcon($('svg', btn), show ? 'eye-off' : 'eye');
    input.focus();
  });
}
for (const input of $$('.gate input[type=password]')) {
  const caps = $('.caps', input.closest('form'));
  const check = (e) => { if (e.getModifierState) caps.hidden = !e.getModifierState('CapsLock'); };
  input.addEventListener('keydown', check);
  input.addEventListener('keyup', check);
  input.addEventListener('blur', () => { caps.hidden = true; });
}

// ---------- Ersteinrichtung ----------

const updateSetupStrength = debounce(async () => {
  const pw = $('#setup-pw').value;
  $('#req-len').classList.toggle('ok', [...pw].length >= 10);
  if (!pw) { setMeter($('#setup-meter'), null); $('#req-strength').classList.remove('ok'); return; }
  const s = await invoke('password_strength', { password: pw });
  setMeter($('#setup-meter'), s.score);
  $('#req-strength').classList.toggle('ok', s.score >= 3);
}, 120);
$('#setup-pw').addEventListener('input', updateSetupStrength);

$('#setup-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = $('#setup-pw').value;
  const err = $('#setup-error');
  err.textContent = '';
  if (pw !== $('#setup-pw2').value) { err.textContent = 'Die Passwörter stimmen nicht überein.'; return; }
  const { score } = await invoke('password_strength', { password: pw });
  if (score < 3 && !(await confirmDialog('Schwaches Master-Passwort',
    'Dieses Passwort ist leicht zu erraten. Wer die Tresor-Datei in die Hände bekommt, kann es durchprobieren. Trotzdem verwenden?',
    'Trotzdem verwenden'))) return;
  try {
    await busy($('#setup-submit'), 'Schlüssel wird abgeleitet…', () => invoke('create_vault', { name: $('#setup-name').value, password: pw }));
    $('#setup-pw').value = $('#setup-pw2').value = '';
    await refreshStatus();
    await enterVault();
    toast('Tresor erstellt', 'shield');
  } catch (ex) { err.textContent = errText(ex); }
});

// ---------- Entsperren ----------

let throttleTimer;
$('#unlock-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = $('#unlock-pw');
  const err = $('#unlock-error');
  const button = $('#unlock-submit');
  err.textContent = '';
  try {
    await busy(button, 'Entsperre…', () => invoke('unlock', { password: input.value }));
    input.value = '';
    await enterVault();
  } catch (ex) {
    const msg = errText(ex);
    err.textContent = msg;
    const card = $('#screen-unlock .gate-card');
    card.classList.remove('shake');
    void card.offsetWidth;
    card.classList.add('shake');
    input.select();
    const wait = /(\d+) s warten/.exec(msg);
    if (wait) startThrottleCountdown(Number(wait[1]));
  }
});

function startThrottleCountdown(secs) {
  const button = $('#unlock-submit');
  const err = $('#unlock-error');
  clearInterval(throttleTimer);
  let left = secs;
  button.disabled = true;
  throttleTimer = setInterval(() => {
    left -= 1;
    if (left <= 0) {
      clearInterval(throttleTimer);
      button.disabled = false;
      err.textContent = '';
      $('#unlock-pw').focus();
    } else {
      err.textContent = `Zu viele Fehlversuche – bitte ${left} s warten`;
    }
  }, 1000);
}

// ---------- Liste ----------

async function reloadEntries() {
  state.entries = await invoke('list_entries');
  state.entries.sort((a, b) => (b.favorite - a.favorite) || a.title.localeCompare(b.title, 'de', { sensitivity: 'base' }));
  if (state.selectedId && !state.entries.some((e) => e.id === state.selectedId)) state.selectedId = null;
  render();
}

function matchesFilter(e, filter) {
  switch (filter) {
    case 'favorites': return e.favorite;
    case 'login': return e.kind === 'login';
    case 'note': return e.kind === 'note';
    case 'totp': return !!e.totp;
    case 'security': return hasIssue(e);
    default: return true;
  }
}

function visibleEntries() {
  const q = state.query.trim().toLowerCase();
  return state.entries.filter((e) => matchesFilter(e, state.filter) && (!q ||
    [e.title, e.username, e.url, e.totp?.issuer, e.totp?.account].some((s) => s && s.toLowerCase().includes(q))));
}

function subtitle(e) {
  if (e.kind === 'note') return 'Sichere Notiz';
  if (e.kind === 'totp') return e.totp?.account || e.totp?.issuer || '2FA-Code';
  return e.username || (e.url ? hostOf(e.url) : '—');
}

function renderFilters() {
  $('#filters').replaceChildren(...FILTERS.map((f) => {
    const n = state.entries.filter((e) => matchesFilter(e, f.key)).length;
    const counter = f.key === 'security'
      ? h('span', { class: `badge${n ? '' : ' ok'}`, text: n ? n : '✓' })
      : h('span', { class: 'count', text: n });
    return h('li', {}, h('button', {
      type: 'button',
      class: `nav-btn${state.filter === f.key ? ' active' : ''}`,
      onclick: () => setFilter(f.key),
    }, icon(f.icon), h('span', { text: f.label }), counter));
  }));
}

async function setFilter(key) {
  if (!(await leaveEditor())) return;
  state.filter = key;
  if (state.selectedId && !visibleEntries().some((e) => e.id === state.selectedId)) selectEntry(null);
  else render();
}

function quickActions(e) {
  const stop = (fn) => (ev) => { ev.stopPropagation(); fn(ev.currentTarget); };
  return h('div', { class: 'quick' },
    e.username ? iconBtn('user', 'Benutzername kopieren', stop((b) => copyField(e.id, 'username', 'Benutzername', b))) : null,
    e.hasPassword ? iconBtn('key', 'Passwort kopieren', stop((b) => copyField(e.id, 'password', 'Passwort', b))) : null,
    e.totp ? iconBtn('timer', '2FA-Code kopieren', stop((b) => copyField(e.id, 'totp', '2FA-Code', b))) : null,
  );
}

function renderList() {
  const list = visibleEntries();
  $('#entries').replaceChildren(...list.map((e) => h('li', {
    class: `entry${e.id === state.selectedId ? ' active' : ''}`,
    role: 'option',
    'aria-selected': String(e.id === state.selectedId),
    'data-id': e.id,
    onclick: () => requestSelect(e.id),
  },
    avatar(e),
    h('div', { class: 'entry-text' },
      h('div', { class: 'entry-title' }, h('span', { text: e.title }), e.favorite ? icon('star', 'fill') : null),
      h('div', { class: 'entry-sub', text: subtitle(e) })),
    h('div', { class: 'entry-side' },
      e.totp ? h('span', { class: 'entry-code', 'data-code': e.id, text: formatCode(state.codes.get(e.id)?.code) })
        : hasIssue(e) ? h('span', { class: 'entry-warn', title: 'Sicherheitsproblem' }, icon('alert')) : null,
      quickActions(e)),
  )));

  const f = FILTERS.find((x) => x.key === state.filter);
  $('#list-title').textContent = state.query ? 'Suchergebnisse' : f.label;
  $('#list-count').textContent = list.length;

  const empty = $('#empty-list');
  empty.hidden = list.length > 0;
  if (!list.length) {
    const [ic, text] = state.entries.length === 0 ? ['lock', 'Noch keine Einträge. Lege mit + den ersten an.']
      : state.query ? ['search', `Nichts gefunden für „${state.query}“.`]
        : state.filter === 'security' ? ['shield', 'Keine Probleme gefunden.']
          : ['grid', 'Hier ist noch nichts.'];
    empty.replaceChildren(icon(ic), h('div', { text }));
  }
}

function render() {
  renderFilters();
  renderList();
  renderDetail();
}

/** Verlässt den Editor; fragt nach, wenn es ungespeicherte Änderungen gibt. */
async function leaveEditor() {
  if (!state.editing) return true;
  if (JSON.stringify(state.editing) !== state.editingOrig &&
    !(await confirmDialog('Änderungen verwerfen?', 'Die Änderungen an diesem Eintrag wurden noch nicht gespeichert.', 'Verwerfen'))) {
    return false;
  }
  state.editing = null;
  return true;
}

async function requestSelect(id) {
  if (id === state.selectedId && !state.editing) return;
  if (!(await leaveEditor())) return;
  selectEntry(id);
}

function selectEntry(id) {
  state.selectedId = id;
  state.notes = null;
  hideRevealed();
  render();
  if (id) $(`.entry[data-id="${CSS.escape(id)}"]`)?.scrollIntoView({ block: 'nearest' });
}

function moveSelection(delta) {
  const list = visibleEntries();
  if (!list.length) return;
  const idx = list.findIndex((e) => e.id === state.selectedId);
  const next = idx < 0 ? (delta > 0 ? 0 : list.length - 1) : Math.max(0, Math.min(list.length - 1, idx + delta));
  requestSelect(list[next].id);
}

// ---------- Detailansicht ----------

function selected() { return state.entries.find((x) => x.id === state.selectedId); }

function frow({ ic, label, value, copy, actions = [] }) {
  const row = h('div', { class: `frow${copy ? ' copyable' : ''}`, title: copy ? 'Klicken zum Kopieren' : null },
    icon(ic, 'ficon'),
    h('div', { class: 'fbody' }, h('div', { class: 'flabel', text: label }), h('div', { class: 'fvalue' }, value)),
    h('div', { class: 'factions' }, actions, copy ? iconBtn('copy', `${label} kopieren`, (ev) => { ev.stopPropagation(); copy(ev.currentTarget); }) : null));
  if (copy) {
    row.addEventListener('click', (ev) => {
      if (ev.target.closest('a, button') || String(window.getSelection())) return;
      copy($('.factions .icon-btn:last-child', row));
    });
  }
  return row;
}

function totpRing(id, R = 15.5) {
  const C = 2 * Math.PI * R;
  return h('div', { class: 'ring', 'data-ring': id, 'data-c': C },
    svgEl('svg', { viewBox: '0 0 36 36' },
      svgEl('circle', { class: 'track', cx: 18, cy: 18, r: R }),
      svgEl('circle', { class: 'prog', cx: 18, cy: 18, r: R, 'stroke-dasharray': C })),
    h('span'));
}

function otpCard(e) {
  const t = e.totp;
  const copyBtn = iconBtn('copy', '2FA-Code kopieren', (ev) => { ev.stopPropagation(); copyField(e.id, 'totp', '2FA-Code', ev.currentTarget); });
  return h('div', { class: 'card' },
    h('div', { class: 'card-title' }, icon('timer', 'sm'), 'Einmalcode'),
    h('div', { class: 'otp', title: 'Klicken zum Kopieren', onclick: () => copyField(e.id, 'totp', '2FA-Code', copyBtn) },
      totpRing(e.id),
      h('div', { class: 'grow' },
        h('div', { class: 'otp-code', 'data-code': e.id, text: formatCode(state.codes.get(e.id)?.code) }),
        h('div', { class: 'otp-meta', text: [t.issuer, t.account].filter(Boolean).join(' · ') || `${t.digits} Ziffern · alle ${t.period} s` })),
      copyBtn));
}

function secretValue(e, key) {
  return isRevealed(e.id, key) ? h('span', { class: 'pw' }, colorize(state.revealed.value)) : h('span', { class: 'masked', text: MASK });
}

function renderDetail() {
  const pane = $('#detail');
  if (state.editing) {
    if (!pane.querySelector('.editor')) pane.replaceChildren(renderEditor(state.editing));
    return;
  }
  const e = selected();
  if (!e) {
    pane.replaceChildren(state.filter === 'security' ? renderReport() : renderPlaceholder());
    return;
  }

  const chips = [];
  if (issues.weak(e)) chips.push(h('span', { class: 'chip danger' }, icon('alert'), 'Schwaches Passwort'));
  if (issues.reused(e)) chips.push(h('span', { class: 'chip danger' }, icon('alert'), 'Mehrfach verwendet'));
  if (issues.old(e)) chips.push(h('span', { class: 'chip warn' }, icon('clock'), 'Über ein Jahr alt'));
  if (e.hasPassword && e.strength >= 3 && !e.reused) chips.push(h('span', { class: 'chip ok' }, icon('shield'), 'Starkes Passwort'));

  const href = safeHref(e.url);
  const fields = [];
  if (e.username) {
    fields.push(frow({ ic: 'user', label: 'Benutzername', value: e.username, copy: (b) => copyField(e.id, 'username', 'Benutzername', b) }));
  }
  if (e.hasPassword) {
    const shown = isRevealed(e.id, 'password');
    const meter = h('div', { class: 'meter inline' }, h('i'), h('i'), h('i'), h('i'));
    setMeter(meter, e.strength);
    fields.push(frow({
      ic: 'key', label: 'Passwort',
      value: [secretValue(e, 'password'), h('div', { class: 'pw-strength' }, meter, STRENGTH_LABEL[e.strength] ?? '')],
      copy: (b) => copyField(e.id, 'password', 'Passwort', b),
      actions: [iconBtn(shown ? 'eye-off' : 'eye', shown ? 'Verbergen' : 'Anzeigen', (ev) => { ev.stopPropagation(); toggleReveal(e.id, 'password'); })],
    }));
  }
  if (e.url) {
    fields.push(frow({
      ic: 'globe', label: 'Website',
      value: href ? h('a', { href, target: '_blank', rel: 'noopener noreferrer', text: e.url }) : e.url,
      copy: (b) => copyField(e.id, 'url', 'Website', b),
      actions: href ? [h('a', { class: 'icon-btn', href, target: '_blank', rel: 'noopener noreferrer', title: 'Öffnen' }, icon('external'))] : [],
    }));
  }

  let notesCard = null;
  if (e.hasNotes) {
    const loaded = state.notes?.id === e.id;
    const body = h('div', { class: `notes${loaded ? '' : ' loading'}`, text: loaded ? state.notes.value : 'Wird entschlüsselt…' });
    notesCard = h('div', { class: 'card' },
      h('div', { class: 'card-title' }, icon('note', 'sm'), h('span', { class: 'grow', text: 'Notizen' }),
        iconBtn('copy', 'Notizen kopieren', (ev) => copyField(e.id, 'notes', 'Notizen', ev.currentTarget))),
      body);
    if (!loaded) {
      invoke('reveal_field', { id: e.id, field: 'notes', index: null }).then((value) => {
        if (state.selectedId !== e.id) return;
        state.notes = { id: e.id, value };
        body.classList.remove('loading');
        body.textContent = value;
      }).catch((err) => { body.textContent = errText(err); });
    }
  }

  let history = null;
  if (e.history.length) {
    history = h('details', { class: 'card history', open: e.history.some((_, i) => isRevealed(e.id, `history:${i}`)) },
      h('summary', {}, icon('history', 'sm'), `Passwortverlauf (${e.history.length})`),
      e.history.map((ts, i) => {
        const shown = isRevealed(e.id, `history:${i}`);
        return frow({
          ic: 'key', label: `Ersetzt am ${fmtDate(ts)}`,
          value: secretValue(e, `history:${i}`),
          copy: (b) => copyField(e.id, 'history', 'Altes Passwort', b, i),
          actions: [iconBtn(shown ? 'eye-off' : 'eye', shown ? 'Verbergen' : 'Anzeigen', (ev) => { ev.stopPropagation(); toggleReveal(e.id, 'history', i); })],
        });
      }));
  }

  pane.replaceChildren(h('div', { class: 'detail-inner' },
    h('div', { class: 'detail-head' },
      avatar(e, true),
      h('div', { class: 'grow' },
        h('h2', { text: e.title }),
        h('div', { class: 'sub' }, h('span', { text: KIND[e.kind].label }),
          href ? [h('span', { text: '·' }), h('a', { href, target: '_blank', rel: 'noopener noreferrer' }, hostOf(e.url), icon('external', 'sm'))] : null)),
      h('div', { class: 'head-actions' },
        iconBtn('star', e.favorite ? 'Aus Favoriten entfernen' : 'Zu Favoriten', () => toggleFavorite(e.id), e.favorite ? 'on' : ''),
        h('button', { type: 'button', class: 'btn', title: 'Bearbeiten (Strg E)', onclick: () => startEdit(e.id) }, icon('pencil'), 'Bearbeiten'),
        iconBtn('trash', 'Löschen (Entf)', () => deleteEntry(e), 'danger'))),
    chips.length ? h('div', { class: 'chips' }, chips) : null,
    e.totp ? otpCard(e) : null,
    fields.length ? h('div', { class: 'card' }, fields) : null,
    notesCard,
    history,
    h('div', { class: 'meta-foot' },
      h('span', {}, icon('clock'), `Geändert ${relTime(e.updatedAt)}`),
      h('span', { text: `Erstellt am ${fmtDate(e.createdAt)}` })),
  ));
  if (e.favorite) $('.head-actions .icon-btn.on svg', pane)?.classList.add('fill');
  updateCodesInDom();
}

function renderPlaceholder() {
  const keys = [['Strg N', 'Neuer Login'], ['Strg F', 'Suchen'], ['↑ ↓', 'Auswählen'], ['Strg L', 'Sperren']];
  return h('div', { class: 'placeholder' }, h('div', {},
    icon(state.entries.length ? 'key' : 'lock'),
    h('p', { text: state.entries.length ? 'Wähle links einen Eintrag aus.' : 'Dein Tresor ist noch leer.' }),
    state.entries.length ? null : h('button', { type: 'button', class: 'btn primary', onclick: () => startNew('login') }, icon('plus'), 'Ersten Login anlegen'),
    h('div', { class: 'keys' }, keys.map(([k, l]) => h('span', {}, h('kbd', { text: k }), ` ${l}`)))));
}

function renderReport() {
  const logins = state.entries.filter((e) => e.hasPassword);
  const groups = [
    { key: 'weak', title: 'Schwache Passwörter', why: 'Leicht zu erraten – durch ein generiertes ersetzen.', cls: 'bad' },
    { key: 'reused', title: 'Mehrfach verwendet', why: 'Ein Leck bei einem Dienst gefährdet alle anderen.', cls: 'bad' },
    { key: 'old', title: 'Älter als ein Jahr', why: 'Seit über einem Jahr nicht geändert.', cls: 'warn' },
    { key: 'noTotp', title: 'Ohne 2FA', why: 'Falls der Dienst es anbietet: 2FA aktivieren.', cls: 'warn' },
  ].map((g) => ({ ...g, items: logins.filter(issues[g.key]) }));

  const bad = new Set(logins.filter(hasIssue).map((e) => e.id));
  const score = logins.length ? Math.round((100 * (logins.length - bad.size)) / logins.length) : 100;
  const R = 42;
  const C = 2 * Math.PI * R;
  const color = score >= 80 ? 'var(--ok)' : score >= 50 ? 'var(--warn)' : 'var(--danger)';
  const prog = svgEl('circle', { class: 'prog', cx: 48, cy: 48, r: R, 'stroke-dasharray': C, 'stroke-dashoffset': C * (1 - score / 100) });
  prog.style.stroke = color;

  const verdict = !logins.length ? 'Noch keine Passwörter zum Prüfen.'
    : !bad.size ? 'Alles im grünen Bereich. Keine schwachen oder doppelten Passwörter.'
      : `${bad.size} von ${logins.length} Passwörtern solltest du ändern.`;

  return h('div', { class: 'detail-inner' },
    h('div', { class: 'card' }, h('div', { class: 'report-hero' },
      h('div', { class: 'score-ring' }, svgEl('svg', { viewBox: '0 0 96 96' }, svgEl('circle', { class: 'track', cx: 48, cy: 48, r: R }), prog), h('span', { text: score })),
      h('div', {}, h('h2', { text: 'Sicherheitswert' }), h('p', { class: 'muted', text: verdict }),
        h('p', { class: 'hint', text: 'Wird lokal berechnet. Passwörter verlassen dabei nie den Tresor.' })))),
    h('div', { class: 'stats' }, groups.map((g) => h('div', { class: `stat${g.items.length ? ` ${g.cls}` : ''}` }, h('b', { text: g.items.length }), h('span', { text: g.title })))),
    groups.filter((g) => g.items.length).map((g) => h('div', { class: 'card' },
      h('div', { class: 'card-title', text: g.title }),
      h('p', { class: 'hint card-hint', text: g.why }),
      g.items.map((e) => h('div', { class: 'issue-row', onclick: () => requestSelect(e.id) },
        avatar(e), h('div', { class: 'grow' }, h('div', { text: e.title }), h('div', { class: 'hint', text: subtitle(e) })),
        icon('external', 'sm'))))),
  );
}

async function toggleFavorite(id) {
  try { await invoke('toggle_favorite', { id }); await reloadEntries(); } catch (e) { toast(errText(e), 'err'); }
}

async function deleteEntry(e) {
  const ok = await confirmDialog('Eintrag löschen?', `„${e.title}“ wird endgültig aus dem Tresor entfernt. Das lässt sich nicht rückgängig machen.`, 'Löschen');
  if (!ok) return;
  try {
    await invoke('delete_entry', { id: e.id });
    const list = visibleEntries();
    const idx = list.findIndex((x) => x.id === e.id);
    state.selectedId = list[idx + 1]?.id ?? list[idx - 1]?.id ?? null;
    state.notes = null;
    await reloadEntries();
    toast('Eintrag gelöscht', 'trash');
  } catch (ex) { toast(errText(ex), 'err'); }
}

// ---------- Editor ----------

function blankTotp() { return { secret: '', algorithm: 'SHA1', digits: 6, period: 30, issuer: '', account: '' }; }

function openEditor(draft) {
  hideRevealed();
  state.editing = draft;
  state.editingOrig = JSON.stringify(draft);
  $('#detail').replaceChildren(renderEditor(draft));
  renderList();
  requestAnimationFrame(() => $(draft.kind === 'totp' && !draft.id ? '#detail [name=secret]' : '#detail [name=title]')?.focus());
}

async function startNew(kind) {
  $('#new-menu').hidden = true;
  if (!(await leaveEditor())) return;
  openEditor({ id: null, kind, title: '', username: '', password: '', url: '', notes: '', favorite: false, totp: kind === 'totp' ? blankTotp() : null });
}

async function startEdit(id) {
  try {
    const full = await invoke('get_entry', { id });
    openEditor({
      id: full.id, kind: full.kind, title: full.title, username: full.username, password: full.password,
      url: full.url, notes: full.notes, favorite: full.favorite, totp: full.totp ? { ...full.totp } : null,
    });
  } catch (e) { toast(errText(e), 'err'); }
}

async function cancelEdit() {
  if (await leaveEditor()) render();
}

function card(title, ic, ...children) {
  return h('div', { class: 'card' }, h('div', { class: 'card-title' }, icon(ic, 'sm'), title), children);
}

function renderEditor(d) {
  const bind = (key, obj = d) => ({ value: obj[key] ?? '', oninput: (ev) => { obj[key] = ev.target.value; } });
  const sections = [];

  sections.push(card('Allgemein', KIND[d.kind].icon,
    h('label', { class: 'field' }, h('span', { text: d.kind === 'totp' ? 'Titel (optional – sonst Name des Dienstes)' : 'Titel' }),
      h('input', { name: 'title', required: d.kind !== 'totp', placeholder: d.kind === 'login' ? 'z. B. GitHub' : '', ...bind('title') }))));

  if (d.kind === 'login') {
    const meter = h('div', { class: 'meter' }, h('i'), h('i'), h('i'), h('i'));
    const label = h('p', { class: 'hint' });
    const updateStrength = debounce(async () => {
      if (!d.password) { setMeter(meter, null); label.textContent = ''; return; }
      const s = await invoke('password_strength', { password: d.password });
      setMeter(meter, s.score);
      label.textContent = `${STRENGTH_LABEL[s.score]} · ≈ ${Math.round(s.bits)} Bit`;
    }, 150);
    const pwInput = h('input', {
      type: 'password', name: 'password', class: 'pw-input', autocomplete: 'new-password', spellcheck: 'false',
      value: d.password, oninput: (ev) => { d.password = ev.target.value; updateStrength(); },
    });
    const eye = iconBtn('eye', 'Anzeigen', () => {
      const showIt = pwInput.type === 'password';
      pwInput.type = showIt ? 'text' : 'password';
      setIcon($('svg', eye), showIt ? 'eye-off' : 'eye');
    });
    const gen = iconBtn('dice', 'Generieren (Strg G)', () => openGenerator((pw) => {
      d.password = pw;
      pwInput.value = pw;
      updateStrength();
    }));
    updateStrength();
    sections.push(card('Zugangsdaten', 'user',
      h('label', { class: 'field' }, h('span', { text: 'Benutzername / E-Mail' }), h('input', { name: 'username', autocomplete: 'off', spellcheck: 'false', ...bind('username') })),
      h('label', { class: 'field' }, h('span', { text: 'Passwort' }), h('div', { class: 'input-wrap' }, pwInput, eye, gen)),
      meter, label,
      h('label', { class: 'field' }, h('span', { text: 'Website' }), h('input', { name: 'url', placeholder: 'https://…', autocomplete: 'off', spellcheck: 'false', ...bind('url') }))));
  }

  if (d.kind !== 'note') sections.push(renderTotpFields(d));

  sections.push(card('Notizen', 'note',
    h('label', { class: 'field' }, h('textarea', { name: 'notes', rows: d.kind === 'note' ? 12 : 4, placeholder: d.kind === 'note' ? 'Wird verschlüsselt gespeichert…' : '', ...bind('notes') })),
    h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: d.favorite, onchange: (ev) => { d.favorite = ev.target.checked; } }), 'Als Favorit markieren')));

  const err = h('p', { class: 'error', role: 'alert' });
  const form = h('form', { class: 'editor detail-inner', autocomplete: 'off', onsubmit: (ev) => { ev.preventDefault(); saveDraft(err); } },
    h('div', { class: 'editor-head' }, avatar({ kind: d.kind, title: d.title || d.kind }, true),
      h('h2', { text: d.id ? `${d.title || KIND[d.kind].label} bearbeiten` : KIND[d.kind].new })),
    sections,
    err,
    h('div', { class: 'editor-actions' },
      h('p', { class: 'hint' }, h('kbd', { text: 'Strg S' }), ' speichern · ', h('kbd', { text: 'Esc' }), ' abbrechen'),
      h('button', { type: 'button', class: 'btn', onclick: cancelEdit }, 'Abbrechen'),
      h('button', { type: 'submit', class: 'btn primary' }, icon('check'), 'Speichern')),
  );
  return form;
}

function renderTotpFields(d) {
  const wrap = h('div', { class: 'card' });
  const preview = h('div', { class: 'otp-preview' });

  const updatePreview = debounce(async () => {
    if (!d.totp || !d.totp.secret.trim() || d.totp.secret.trim().toLowerCase().startsWith('otpauth://')) { preview.replaceChildren(); return; }
    try {
      const code = await invoke('totp_preview', { config: d.totp });
      preview.replaceChildren(icon('check', 'sm'), 'Aktueller Code:', h('b', { text: formatCode(code) }));
      preview.style.color = '';
    } catch (e) {
      preview.replaceChildren(icon('alert', 'sm'), errText(e));
      preview.style.color = 'var(--danger)';
    }
  }, 250);

  const draw = () => {
    const t = d.totp;
    const title = h('div', { class: 'card-title' }, icon('timer', 'sm'), d.kind === 'login' ? 'Zwei-Faktor (optional)' : 'Zwei-Faktor');
    if (!t) {
      wrap.replaceChildren(title, h('p', { class: 'hint', text: 'Speichere den 2FA-Schlüssel direkt beim Login – dann ist der Code immer griffbereit.' }),
        h('button', { type: 'button', class: 'btn mt', onclick: () => { d.totp = blankTotp(); draw(); $('[name=secret]', wrap).focus(); } }, icon('plus'), '2FA hinzufügen'));
      return;
    }
    const tBind = (key, numeric = false) => ({
      value: t[key] ?? '',
      oninput: (ev) => { t[key] = numeric ? Number(ev.target.value) : ev.target.value; updatePreview(); },
    });
    const secret = h('input', {
      type: t.secret ? 'password' : 'text',
      name: 'secret', class: 'pw-input', autocomplete: 'off', spellcheck: 'false',
      placeholder: 'Base32-Schlüssel oder otpauth://-Link einfügen', value: t.secret,
      oninput: (ev) => { t.secret = ev.target.value; updatePreview(); },
      onchange: async (ev) => {
        const v = ev.target.value.trim();
        if (!v.toLowerCase().startsWith('otpauth://')) return;
        try {
          d.totp = await invoke('parse_otpauth', { uri: v });
          if (!d.title) {
            d.title = d.totp.issuer;
            const ti = $('#detail [name=title]');
            if (ti) ti.value = d.title;
          }
          draw();
          toast('otpauth-Link übernommen');
        } catch (e) { toast(errText(e), 'err'); }
      },
    });
    const secretEye = iconBtn(secret.type === 'password' ? 'eye' : 'eye-off', 'Anzeigen', () => {
      const showIt = secret.type === 'password';
      secret.type = showIt ? 'text' : 'password';
      setIcon($('svg', secretEye), showIt ? 'eye-off' : 'eye');
    });
    const select = (key, options) => h('select', {
      onchange: (ev) => { t[key] = key === 'algorithm' ? ev.target.value : Number(ev.target.value); updatePreview(); },
    }, options.map(([v, l]) => h('option', { value: String(v), selected: String(t[key]) === String(v), text: l })));

    wrap.replaceChildren(
      title,
      h('label', { class: 'field' }, h('span', { text: 'Geheimer Schlüssel' }),
        h('div', { class: 'input-wrap' }, secret, secretEye,
          d.kind === 'login' ? iconBtn('x', '2FA entfernen', () => { d.totp = null; draw(); }) : null)),
      preview,
      h('div', { class: 'row2' },
        h('label', { class: 'field' }, h('span', { text: 'Dienst' }), h('input', { placeholder: 'z. B. GitHub', ...tBind('issuer') })),
        h('label', { class: 'field' }, h('span', { text: 'Konto' }), h('input', { placeholder: 'z. B. name@mail.de', ...tBind('account') }))),
      h('details', { class: 'adv' }, h('summary', { text: 'Erweitert (Algorithmus, Ziffern, Intervall)' }),
        h('div', { class: 'row3' },
          h('label', { class: 'field' }, h('span', { text: 'Algorithmus' }), select('algorithm', [['SHA1', 'SHA-1'], ['SHA256', 'SHA-256'], ['SHA512', 'SHA-512']])),
          h('label', { class: 'field' }, h('span', { text: 'Ziffern' }), select('digits', [[6, '6'], [7, '7'], [8, '8']])),
          h('label', { class: 'field' }, h('span', { text: 'Intervall (s)' }), h('input', { type: 'number', min: 1, max: 300, ...tBind('period', true) })))),
    );
    updatePreview();
  };
  draw();
  return wrap;
}

async function saveDraft(err) {
  err.textContent = '';
  try {
    const id = await invoke('save_entry', { entry: state.editing });
    state.editing = null;
    state.selectedId = id;
    state.notes = null;
    await reloadEntries();
    refreshCodes();
    toast('Gespeichert');
  } catch (e) { err.textContent = errText(e); }
}

// ---------- TOTP-Ticker ----------

function updateCodesInDom() {
  for (const el of $$('[data-code]')) {
    const c = state.codes.get(el.dataset.code);
    el.textContent = formatCode(c?.code);
    el.classList.toggle('soon', !!c && c.remaining <= 5);
  }
  for (const el of $$('[data-ring]')) {
    const c = state.codes.get(el.dataset.ring);
    if (!c) continue;
    const C = Number(el.dataset.c);
    $('.prog', el).style.strokeDashoffset = String(C * (1 - c.remaining / c.period));
    el.classList.toggle('soon', c.remaining <= 5);
    $('span', el).textContent = c.remaining;
  }
}

async function refreshCodes() {
  if (!state.unlocked || !state.entries.some((e) => e.totp)) return;
  try {
    const codes = await invoke('totp_codes');
    state.codes = new Map(codes.map((c) => [c.id, c]));
    updateCodesInDom();
  } catch { /* gesperrt */ }
}

setInterval(() => {
  updateClipPill();
  if (!state.unlocked) return;
  if (settings.autoLockMin > 0 && Date.now() - state.lastActivity > settings.autoLockMin * 60_000) {
    lockVault('Wegen Inaktivität gesperrt');
    return;
  }
  refreshCodes();
}, 1000);

for (const ev of ['pointerdown', 'keydown', 'wheel', 'pointermove']) {
  window.addEventListener(ev, () => { state.lastActivity = Date.now(); }, { passive: true });
}

function updateAutolockHint() {
  $('#autolock-hint').textContent = settings.autoLockMin > 0
    ? `Sperrt nach ${settings.autoLockMin === 60 ? '1 Std.' : `${settings.autoLockMin} Min.`} Inaktivität`
    : 'Automatische Sperre aus';
}

// ---------- Generator ----------

let genCallback = null;
let genCurrent = '';

function openGenerator(onUse = null) {
  genCallback = onUse;
  const g = settings.gen;
  $('#gen-length').value = g.length;
  $('#gen-lower').checked = g.lower;
  $('#gen-upper').checked = g.upper;
  $('#gen-digits').checked = g.digits;
  $('#gen-symbols').checked = g.symbols;
  $('#gen-ambiguous').checked = g.avoidAmbiguous;
  $('#gen-use').hidden = !onUse;
  $('#dlg-generator').showModal();
  regenerate();
}

async function regenerate() {
  const g = settings.gen = {
    length: Number($('#gen-length').value),
    lower: $('#gen-lower').checked,
    upper: $('#gen-upper').checked,
    digits: $('#gen-digits').checked,
    symbols: $('#gen-symbols').checked,
    avoidAmbiguous: $('#gen-ambiguous').checked,
  };
  saveSettings();
  $('#gen-length-label').textContent = g.length;
  try {
    const r = await invoke('generate_password', { options: g });
    genCurrent = r.password;
    $('#gen-output').replaceChildren(colorize(r.password));
    const score = scoreFromBits(r.entropyBits);
    setMeter($('#gen-meter'), score);
    $('#gen-entropy').textContent = `${STRENGTH_LABEL[score]} · ≈ ${Math.round(r.entropyBits)} Bit Entropie`;
  } catch (e) {
    genCurrent = '';
    $('#gen-output').replaceChildren();
    setMeter($('#gen-meter'), null);
    $('#gen-entropy').textContent = errText(e);
  }
}

$('#gen-form').addEventListener('input', regenerate);
$('#gen-refresh').addEventListener('click', regenerate);
$('#gen-copy').addEventListener('click', async (ev) => {
  if (!genCurrent) return;
  const btn = ev.currentTarget;
  try {
    await invoke('copy_text', { text: genCurrent, clearAfter: settings.clipClearSec });
    copied('Passwort', btn);
  } catch (e) { toast(errText(e), 'err'); }
});
$('#gen-use').addEventListener('click', () => {
  if (genCurrent && genCallback) genCallback(genCurrent);
  $('#dlg-generator').close();
});
$('#dlg-generator').addEventListener('close', () => { genCallback = null; genCurrent = ''; $('#gen-output').replaceChildren(); });

// ---------- Einstellungen ----------

$('#btn-settings').addEventListener('click', () => {
  $('#set-autolock').value = String(settings.autoLockMin);
  $('#set-clip').value = String(settings.clipClearSec);
  $('#set-minimize').checked = settings.lockOnMinimize;
  $('#set-protect').checked = settings.contentProtected;
  for (const id of ['master-error', 'import-error', 'duress-error']) $(`#${id}`).textContent = '';
  setMeter($('#master-meter'), null);
  invoke('duress_status').then(updateDuressUi).catch(() => {});
  $('#dlg-settings').showModal();
});
$('#settings-close').addEventListener('click', () => $('#dlg-settings').close());
$('#dlg-settings').addEventListener('close', () => {
  for (const id of ['master-old', 'master-new', 'master-new2', 'import-text', 'duress-master', 'duress-pw', 'duress-pw2']) $(`#${id}`).value = '';
});

function updateDuressUi(set) {
  const st = $('#duress-state');
  st.replaceChildren(icon(set ? 'shield' : 'info', 'sm'),
    set ? 'Für diesen Tresor ist ein Notfall-Passwort eingerichtet.' : 'Für diesen Tresor ist kein Notfall-Passwort eingerichtet.');
  st.classList.toggle('on', set);
  $('#duress-submit').textContent = set ? 'Notfall-Passwort ändern' : 'Notfall-Passwort einrichten';
  $('#duress-remove').hidden = !set;
}

$('#duress-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('#duress-error');
  err.textContent = '';
  const duress = $('#duress-pw').value;
  if (!duress) { err.textContent = 'Bitte ein Notfall-Passwort eingeben.'; return; }
  if (duress !== $('#duress-pw2').value) { err.textContent = 'Die Notfall-Passwörter stimmen nicht überein.'; return; }
  const ok = await confirmDialog('Notfall-Passwort festlegen?',
    'Wer dieses Passwort beim Entsperren eingibt, löscht diesen Tresor sofort und unwiderruflich. Wähle eins, das du dir merkst, aber niemals mit dem Master-Passwort verwechselst.',
    'Festlegen');
  if (!ok) return;
  try {
    await busy($('#duress-submit'), 'Wird eingerichtet…', () => invoke('set_duress', { master: $('#duress-master').value, duress }));
    for (const id of ['duress-master', 'duress-pw', 'duress-pw2']) $(`#${id}`).value = '';
    updateDuressUi(true);
    toast('Notfall-Passwort eingerichtet', 'shield');
  } catch (ex) { err.textContent = errText(ex); }
});

$('#duress-remove').addEventListener('click', async () => {
  const err = $('#duress-error');
  err.textContent = '';
  if (!$('#duress-master').value) { err.textContent = 'Zum Entfernen bitte das Master-Passwort eingeben.'; $('#duress-master').focus(); return; }
  try {
    await busy($('#duress-remove'), 'Wird entfernt…', () => invoke('remove_duress', { master: $('#duress-master').value }));
    for (const id of ['duress-master', 'duress-pw', 'duress-pw2']) $(`#${id}`).value = '';
    updateDuressUi(false);
    toast('Notfall-Passwort entfernt');
  } catch (ex) { err.textContent = errText(ex); }
});
$('#set-autolock').addEventListener('change', (e) => { settings.autoLockMin = Number(e.target.value); saveSettings(); updateAutolockHint(); });
$('#set-clip').addEventListener('change', (e) => { settings.clipClearSec = Number(e.target.value); saveSettings(); });
$('#set-minimize').addEventListener('change', (e) => { settings.lockOnMinimize = e.target.checked; saveSettings(); applyWindowSettings(); });
$('#set-protect').addEventListener('change', (e) => { settings.contentProtected = e.target.checked; saveSettings(); applyWindowSettings(); });

$('#master-new').addEventListener('input', debounce(async (e) => {
  const pw = e.target.value;
  setMeter($('#master-meter'), pw ? (await invoke('password_strength', { password: pw })).score : null);
}, 150));

$('#master-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('#master-error');
  err.textContent = '';
  if ($('#master-new').value !== $('#master-new2').value) { err.textContent = 'Die neuen Passwörter stimmen nicht überein.'; return; }
  try {
    await busy($('#master-submit'), 'Wird neu verschlüsselt…', () => invoke('change_master', { current: $('#master-old').value, new: $('#master-new').value }));
    for (const id of ['master-old', 'master-new', 'master-new2']) $(`#${id}`).value = '';
    setMeter($('#master-meter'), null);
    toast('Master-Passwort geändert', 'shield');
  } catch (ex) { err.textContent = errText(ex); }
});

$('#import-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('#import-error');
  err.textContent = '';
  try {
    const n = await invoke('import_otpauth', { text: $('#import-text').value });
    $('#import-text').value = '';
    await reloadEntries();
    refreshCodes();
    toast(`${n} 2FA-${n === 1 ? 'Eintrag' : 'Einträge'} importiert`);
  } catch (ex) { err.textContent = errText(ex); }
});

// ---------- Leiste & Tastatur ----------

$('#search').addEventListener('input', (e) => { state.query = e.target.value; renderList(); });
$('#btn-lock').addEventListener('click', () => lockVault());
$('#btn-generator').addEventListener('click', () => openGenerator());
$('#btn-shortcuts').addEventListener('click', () => $('#dlg-shortcuts').showModal());
$('#btn-new').addEventListener('click', (e) => { e.stopPropagation(); $('#new-menu').hidden = !$('#new-menu').hidden; });
for (const b of $$('[data-new]')) b.addEventListener('click', () => startNew(b.dataset.new));
document.addEventListener('click', () => { $('#new-menu').hidden = true; });

document.addEventListener('keydown', (e) => {
  if (!state.unlocked) return;
  const ctrl = e.ctrlKey || e.metaKey;
  const key = e.key.toLowerCase();
  if (ctrl && key === 'l') { e.preventDefault(); lockVault(); return; }
  if ($('dialog[open]')) return;

  if (ctrl && key === 'f') { e.preventDefault(); $('#search').focus(); $('#search').select(); return; }
  if (ctrl && key === 'g') { e.preventDefault(); openGenerator(); return; }
  if (ctrl && key === 'n') { e.preventDefault(); startNew('login'); return; }

  if (state.editing) {
    if (ctrl && key === 's') { e.preventDefault(); $('#detail form.editor')?.requestSubmit(); }
    else if (e.key === 'Escape') { e.preventDefault(); cancelEdit(); }
    return;
  }

  const inSearch = document.activeElement === $('#search');
  if ((e.key === 'ArrowDown' || e.key === 'ArrowUp') && (inSearch || !isTyping())) {
    e.preventDefault();
    moveSelection(e.key === 'ArrowDown' ? 1 : -1);
    return;
  }
  if (inSearch && e.key === 'Escape' && state.query) { $('#search').value = state.query = ''; renderList(); return; }
  if (isTyping() && !inSearch) return;

  const sel = selected();
  if (!sel) return;
  const noTextSelected = !String(window.getSelection());
  if (ctrl && key === 'c' && sel.hasPassword && noTextSelected && !inSearch) { e.preventDefault(); copyField(sel.id, 'password', 'Passwort'); }
  else if (ctrl && key === 'b' && sel.username) { e.preventDefault(); copyField(sel.id, 'username', 'Benutzername'); }
  else if (ctrl && key === 't' && sel.totp) { e.preventDefault(); copyField(sel.id, 'totp', '2FA-Code'); }
  else if (ctrl && key === 'e') { e.preventDefault(); startEdit(sel.id); }
  else if (e.key === 'Delete' && !inSearch) { e.preventDefault(); deleteEntry(sel); }
});

// Kein Browser-Kontextmenü (Neu laden etc.) außerhalb von Eingabefeldern.
document.addEventListener('contextmenu', (e) => {
  if (!e.target.closest('input, textarea')) e.preventDefault();
});

init().catch((e) => toast(errText(e), 'err'));
