/* Hifa 1.1 · versión local (persona y profesional)
   Todo vive en este dispositivo (IndexedDB), cifrado con AES-GCM 256.
   La llave se deriva de tu clave con PBKDF2-SHA256 (600.000 iteraciones) y solo existe en memoria.
   No hay servidor: nada sale del dispositivo salvo lo que tú exportes o compartas. */
'use strict';

/* ---------------- utilidades ---------------- */
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const dkey = (d = new Date()) => new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 10);
const addDays = (k, n) => { const d = new Date(k + 'T12:00:00'); d.setDate(d.getDate() + n); return dkey(d); };
const fmtD = k => new Date(k + 'T12:00:00').toLocaleDateString('es-CO', { day: 'numeric', month: 'short' });
const daysBetween = (a, b) => Math.round((new Date(b + 'T12:00:00') - new Date(a + 'T12:00:00')) / 864e5);
const num = n => (n == null || isNaN(n)) ? '–' : n.toLocaleString('es-CO', { maximumFractionDigits: 1 });
const nowHM = () => new Date().toTimeString().slice(0, 5);
const uid = () => Math.random().toString(36).slice(2, 9);
function isoWeek(d = new Date()) {
  const t = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
  const day = t.getUTCDay() || 7; t.setUTCDate(t.getUTCDate() + 4 - day);
  const y0 = new Date(Date.UTC(t.getUTCFullYear(), 0, 1));
  return t.getUTCFullYear() + '-W' + String(Math.ceil(((t - y0) / 864e5 + 1) / 7)).padStart(2, '0');
}
let toastT;
function toast(t) { const e = $('#toast'); e.textContent = t; e.hidden = false; clearTimeout(toastT); toastT = setTimeout(() => e.hidden = true, 2800); }
function vibrate() { if (D && !D.prefs.novib && navigator.vibrate) try { navigator.vibrate(12); } catch (e) {} }
const TODAY = () => dkey();

/* ---------------- almacenamiento (IndexedDB) ---------------- */
const DB = {
  db: null,
  open() { return new Promise((res, rej) => { const r = indexedDB.open('hifa-demo-profesional', 1); r.onupgradeneeded = () => r.result.createObjectStore('kv'); r.onsuccess = () => { this.db = r.result; res(); }; r.onerror = () => rej(r.error); }); },
  get(k) { return new Promise((res, rej) => { const q = this.db.transaction('kv').objectStore('kv').get(k); q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error); }); },
  set(k, v) { return new Promise((res, rej) => { const tx = this.db.transaction('kv', 'readwrite'); tx.objectStore('kv').put(v, k); tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error); }); },
  del(k) { return new Promise((res, rej) => { const tx = this.db.transaction('kv', 'readwrite'); tx.objectStore('kv').delete(k); tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error); }); },
  clear() { return new Promise((res, rej) => { const tx = this.db.transaction('kv', 'readwrite'); tx.objectStore('kv').clear(); tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error); }); }
};

/* ---------------- cifrado ---------------- */
const ITER = 600000;
function b64(buf) { const u = new Uint8Array(buf); let s = ''; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(s); }
function unb64(s) { const b = atob(s), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
async function deriveKey(pass, salt, iter = ITER) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass.normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function seal(obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, KEY, new TextEncoder().encode(JSON.stringify(obj)));
  return { app: 'hifa', format: 1, kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: ITER, salt: b64(SALT) }, cipher: 'AES-GCM', iv: b64(iv), data: b64(ct) };
}
async function unseal(env, key) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(env.iv) }, key, unb64(env.data));
  return JSON.parse(new TextDecoder().decode(pt));
}
/* paquetes paciente → profesional: ECDH P-256 + HKDF + AES-GCM.
   El profesional tiene un par de llaves; su llave pública es su «código».
   Cada paquete usa una llave efímera: solo la llave privada del profesional puede abrirlo. */
const b64u = buf => b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => unb64(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
async function fingerprint(raw) { const h = new Uint8Array(await crypto.subtle.digest('SHA-256', raw)); return [...h.slice(0, 6)].map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase().match(/.{4}/g).join('-'); }
const ECDH = { name: 'ECDH', namedCurve: 'P-256' };
async function newProKeys() {
  const kp = await crypto.subtle.generateKey(ECDH, true, ['deriveBits']);
  const pub = await crypto.subtle.exportKey('raw', kp.publicKey);
  return { pub: b64u(pub), priv: await crypto.subtle.exportKey('jwk', kp.privateKey), fp: await fingerprint(pub) };
}
async function shareKey(privKey, pubKey) {
  const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: pubKey }, privKey, 256);
  const hk = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode('hifa-share-v1'), info: new Uint8Array() }, hk, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function sealFor(proPub, obj) {
  const raw = unb64u(proPub), pub = await crypto.subtle.importKey('raw', raw, ECDH, false, []);
  const eph = await crypto.subtle.generateKey(ECDH, true, ['deriveBits']);
  const k = await shareKey(eph.privateKey, pub), iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode(JSON.stringify(obj)));
  return { app: 'hifa', type: 'paquete-paciente', format: 1, to: await fingerprint(raw), epk: b64u(await crypto.subtle.exportKey('raw', eph.publicKey)), iv: b64(iv), data: b64(ct) };
}
async function openFromPatient(env) {
  const priv = await crypto.subtle.importKey('jwk', D.pro.priv, ECDH, false, ['deriveBits']);
  const epk = await crypto.subtle.importKey('raw', unb64u(env.epk), ECDH, false, []);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(env.iv) }, await shareKey(priv, epk), unb64(env.data));
  return JSON.parse(new TextDecoder().decode(pt));
}
async function parseProCode(str) {
  const m = String(str).trim().match(/HIFA-PRO1\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]*)/);
  if (!m) throw new Error('codigo');
  const raw = unb64u(m[1]); if (raw.length !== 65) throw new Error('codigo');
  await crypto.subtle.importKey('raw', raw, ECDH, false, []);
  return { pub: m[1], name: new TextDecoder().decode(unb64u(m[2] || '')), fp: await fingerprint(raw) };
}
function validEnvelope(env) { return env && env.app === 'hifa' && env.kdf && env.kdf.salt && env.iv && env.data; }

/* ---------------- estado ---------------- */
let KEY = null, SALT = null, D = null, META = { lastBackup: null };
const isPro = () => D && D.role === 'pro';
const DEFAULT_HABITS = [['Dormir 7 horas o más'], ['Tomar 2 L de agua'], ['Moverme 20 min'], ['Meditar o respirar 5 min'], ['Desayuno con proteína', true], ['Pantallas fuera 30 min antes de dormir']];
function freshState() {
  return {
    v: 1, role: 'patient', shareId: uid() + uid() + uid(), created: new Date().toISOString(), days: {},
    habits: DEFAULT_HABITS.map(([n, food]) => ({ id: uid(), n, food: !!food })), hlog: {},
    routine: [], scales: [], purpose: { compass: '', values: ['Calma', 'Creatividad', 'Autenticidad', 'Aprender'], valuesOn: [] },
    phrase: null, reportTopics: '',
    prefs: { minds: [], goals: [], view: 'simple', showIntake: true, noanim: false, novib: false, soft: false, literal: false, sensory: false, backupEvery: 7, theme: 'auto', welcomed: false },
    support: { psyName: '', psyPhone: '', nextSession: '', alias: '', proKey: null, lastSent: null, scopes: null }
  };
}
function freshProBase() {
  return { v: 1, role: 'pro', created: new Date().toISOString(), pro: { name: '', pub: '', priv: null, fp: '' }, patients: {},
    prefs: { ...freshState().prefs, welcomed: true } };
}
async function freshPro() { const d = freshProBase(); d.pro = { name: '', ...(await newProKeys()) }; return d; }
function migrate(d) {
  if (d.role === 'pro') {
    const f = freshProBase();
    for (const k of Object.keys(f)) if (d[k] === undefined) d[k] = f[k];
    for (const k of Object.keys(f.prefs)) if (d.prefs[k] === undefined) d.prefs[k] = f.prefs[k];
    return d;
  }
  const f = freshState();
  if (!d.role) d.role = 'patient';
  if (!d.shareId) d.shareId = f.shareId;
  if (d.support) for (const k of Object.keys(f.support)) if (d.support[k] === undefined) d.support[k] = f.support[k];
  for (const k of Object.keys(f)) if (d[k] === undefined) d[k] = f[k];
  for (const k of Object.keys(f.prefs)) if (d.prefs[k] === undefined) d.prefs[k] = f.prefs[k];
  for (const k of Object.keys(f.purpose)) if (d.purpose[k] === undefined) d.purpose[k] = f.purpose[k];
  return d;
}
const dayR = (k = TODAY()) => D.days[k] || {};
const dayW = (k = TODAY()) => (D.days[k] ||= {});
const hasData = e => e && (e.mood || e.en || e.an || e.fo || e.su || (e.intake && e.intake.length) || (e.journal && e.journal.length) || e.sens);

/* guardado con cola: nunca se pisan dos escrituras */
let saveChain = Promise.resolve(), saveT = null;
function save(now = false) {
  $('#saveState').textContent = 'Guardando…';
  clearTimeout(saveT);
  const run = () => { saveChain = saveChain.then(async () => {
    const env = await seal(D); await DB.set('vault', env);
    $('#saveState').textContent = 'Guardado ✓';
    scheduleFileWrite(env);
  }).catch(e => { console.error(e); $('#saveState').textContent = 'No se pudo guardar'; toast('No se pudo guardar. Revisa el espacio del dispositivo.'); }); return saveChain; };
  if (now) return run();
  saveT = setTimeout(run, 350);
}
async function setMeta(patch) { META = { ...META, ...patch }; await DB.set('meta', META); }

/* ---------------- pantalla de clave ---------------- */
function lockView(which) {
  ['fNew', 'fUnlock', 'fRestore', 'lockBusy'].forEach(id => $('#' + id).hidden = id !== which);
  $('#lockErr').hidden = true;
}
function lockErr(t) { $('#lockErr').textContent = t; $('#lockErr').hidden = false; }
function busy(t) { $('#lockBusyText').textContent = t; lockView('lockBusy'); }
let lockPrev = 'fUnlock';

async function boot() {
  if (!window.crypto || !crypto.subtle) { lockView(null); lockErr('Este navegador no permite cifrar. Abre Hifa desde una dirección https:// (no como archivo) y en un navegador actualizado.'); return; }
  try { await DB.open(); } catch (e) { lockErr('Este navegador no permite guardar datos (¿modo incógnito?). Abre Hifa en una ventana normal.'); return; }
  META = (await DB.get('meta')) || { lastBackup: null };
  const vault = await DB.get('vault');
  lockPrev = vault ? 'fUnlock' : 'fNew';
  lockView(lockPrev);
  setTimeout(() => (vault ? $('#up') : $('#np1')).focus(), 50);
  if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost')) void 0;
}

$('#fNew').addEventListener('submit', async e => {
  e.preventDefault();
  const a = $('#np1').value, b = $('#np2').value;
  if (a.length < 8) return lockErr('La clave debe tener al menos 8 caracteres.');
  if (a !== b) return lockErr('Las claves no coinciden.');
  if (!$('#npOk').checked) return lockErr('Marca la casilla para confirmar que entiendes.');
  busy('Creando tu bitácora cifrada…');
  SALT = crypto.getRandomValues(new Uint8Array(16));
  KEY = await deriveKey(a, SALT);
  D = newRole === 'pro' ? await freshPro() : freshState();
  await save(true);
  $('#np1').value = $('#np2').value = '';
  enterApp();
});
$('#fUnlock').addEventListener('submit', async e => {
  e.preventDefault();
  const p = $('#up').value; if (!p) return;
  busy('Abriendo…');
  try {
    const env = await DB.get('vault');
    SALT = unb64(env.kdf.salt);
    KEY = await deriveKey(p, SALT, env.kdf.iterations || ITER);
    D = migrate(await unseal(env, KEY));
    $('#up').value = '';
    enterApp();
  } catch (err) { KEY = null; lockView('fUnlock'); lockErr('Clave incorrecta. Inténtalo de nuevo.'); $('#up').select(); }
});
let newRole = 'patient';
$('#roleNew').onclick = e => { const b = e.target.closest('button'); if (!b) return; newRole = b.dataset.r; $$('#roleNew button').forEach(x => x.setAttribute('aria-pressed', x === b)); };
$('#toRestore').onclick = $('#toRestore2').onclick = () => lockView('fRestore');
$('#backFromRestore').onclick = () => lockView(lockPrev);
$('#fRestore').addEventListener('submit', async e => {
  e.preventDefault();
  const f = $('#rf').files[0], p = $('#rp').value;
  if (!f || !p) return;
  busy('Restaurando copia…');
  try {
    const env = JSON.parse(await f.text());
    if (!validEnvelope(env)) throw new Error('formato');
    const salt = unb64(env.kdf.salt), key = await deriveKey(p, salt, env.kdf.iterations || ITER);
    const data = migrate(await unseal(env, key));
    SALT = salt; KEY = key; D = data;
    await save(true);
    await setMeta({ lastBackup: new Date().toISOString() });
    $('#rp').value = '';
    enterApp(); toast('Copia restaurada');
  } catch (err) { lockView('fRestore'); lockErr(err.message === 'formato' ? 'Ese archivo no es una copia de Hifa.' : 'No se pudo abrir: revisa la clave de esa copia.'); }
});
$('#wipeLocked').onclick = async () => {
  if (!confirm('Se borrarán todos los datos de Hifa en este dispositivo. No se puede deshacer. ¿Continuar?')) return;
  await DB.clear(); location.reload();
};

/* bloqueo automático tras 5 minutos en segundo plano */
let hiddenAt = 0;
document.addEventListener('visibilitychange', () => {
  if (!KEY) return;
  if (document.hidden) hiddenAt = Date.now();
  else if (hiddenAt && Date.now() - hiddenAt > 5 * 60 * 1000) lockNow();
});
async function lockNow() { try { await saveChain; } catch (e) {} location.reload(); }

/* ---------------- entrar a la app ---------------- */
function enterApp() {
  $('#lock').hidden = true; $('#app').hidden = false; $('#tabs').hidden = false;
  if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
  const pro = isPro();
  document.body.classList.toggle('pro', pro);
  $('#tabs').hidden = pro; $('#tabsPro').hidden = !pro; $('#btnHelp').hidden = pro;
  if (pro) $('#ajustesBox').appendChild($('#dataCard'));
  applyPrefs(); renderAll(); go(pro ? 'pacientes' : 'hoy');
  initFileBackup();
}
function renderAll() {
  if (isPro()) { renderPatients(); renderCodigo(); renderAjustes(); renderBackupState(); }
  else { renderHoy(); renderHabits(); renderYo(); }
}

/* ---------------- navegación ---------------- */
const VIEWS = ['hoy', 'bitacora', 'panel', 'escala', 'habitos', 'yo', 'informe', 'enviar', 'pacientes', 'paciente', 'codigo', 'ajustes'];
function go(t) {
  VIEWS.forEach(v => $('#v-' + v).hidden = v !== t);
  const tab = { escala: 'panel', informe: 'panel', enviar: 'yo', paciente: 'pacientes' }[t] || t;
  $$('nav.tabs button').forEach(b => b.dataset.tab === tab ? b.setAttribute('aria-current', 'page') : b.removeAttribute('aria-current'));
  if (t === 'hoy') renderHoy();
  if (t === 'bitacora') renderChat();
  if (t === 'panel') renderPanel();
  if (t === 'habitos') renderHabits();
  if (t === 'yo') renderYo();
  if (t === 'informe') buildReport();
  if (t === 'enviar') renderEnviar();
  if (t === 'pacientes') renderPatients();
  if (t === 'paciente') renderPatient();
  if (t === 'codigo') renderCodigo();
  if (t === 'ajustes') renderAjustes();
  window.scrollTo(0, 0);
}
document.addEventListener('click', e => {
  const t = e.target.closest('[data-tab]'); if (t) return go(t.dataset.tab);
  const g = e.target.closest('[data-go]'); if (g) return go(g.dataset.go);
});

/* ---------------- ayuda ---------------- */
function helpLinks() {
  const s = (D && D.support) || {};
  let h = '<a href="tel:123"><b>123 · Emergencias</b><span>Si estás en peligro ahora</span></a>' +
    '<a href="tel:192"><b>Línea 192, opción 4</b><span>Salud mental · nacional · 24 h</span></a>' +
    '<a href="tel:+576044444448"><b>Línea Amiga Medellín</b><span>604 444 4448</span></a>';
  if (s.psyPhone) h += `<a href="tel:${esc(s.psyPhone.replace(/[^\d+]/g, ''))}"><b>${esc(s.psyName || 'Mi psicólogx')}</b><span>${esc(s.psyPhone)}</span></a>`;
  return h;
}
function openHelp() { $('#helpLinks').innerHTML = helpLinks(); $('#helpDlg').showModal(); }
$('#btnHelp').onclick = openHelp;
$('#helpClose').onclick = () => $('#helpDlg').close();

/* ---------------- diálogo de clave ---------------- */
function askPass(msg, confirmTwice = false) {
  return new Promise(res => {
    $('#passMsg').textContent = msg; $('#passIn').value = ''; $('#passIn2').value = '';
    $('#passIn2L').hidden = !confirmTwice;
    const dlg = $('#passDlg');
    dlg.onclose = () => {
      if (dlg.returnValue !== 'ok') return res(null);
      const a = $('#passIn').value, b = $('#passIn2').value;
      if (confirmTwice && a !== b) { toast('Las claves no coinciden'); return res(null); }
      res(a || null);
    };
    dlg.returnValue = ''; dlg.showModal(); setTimeout(() => $('#passIn').focus(), 50);
  });
}

/* ---------------- preferencias ---------------- */
const GROUPS = {
  g1: ['Ánimo bajo o depresión', 'Ansiedad', 'Estrés', 'Burnout', 'Duelo', 'Autoestima', 'Bipolaridad o cambios de ánimo intensos'],
  g2: ['Trauma o estrés postraumático', 'Relaciones', 'Identidad (género, orientación)'],
  g3: ['Sueño o insomnio', 'Dolor crónico', 'Pensamientos repetitivos (TOC)', 'Relación con la comida', 'Historial de psicosis (propio o familiar)'],
  g4: ['Sustancias', 'Alcohol', 'Pantallas'], g5: ['Hábitos', 'Propósito', 'Integración psicodélica']
};
const MINDS = ['TDAH', 'Autismo', 'Altas capacidades', 'Dislexia u otras diferencias de aprendizaje', 'Tourette o tics', 'Prefiero no decir'];
const riskFlag = () => D.prefs.goals.includes('Bipolaridad o cambios de ánimo intensos') || D.prefs.goals.includes('Historial de psicosis (propio o familiar)');
const tca = () => D.prefs.goals.includes('Relación con la comida');
function applyPrefs() {
  const p = D.prefs;
  document.body.classList.toggle('noanim', p.noanim);
  document.body.classList.toggle('soft', p.soft);
  if (p.theme === 'auto') delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = p.theme;
  $$('.detail').forEach(e => e.hidden = p.view !== 'det' && !e.dataset.force);
}
function chips(el, list, isOn, toggle, cls = '') {
  el.innerHTML = list.map(t => `<button type="button" class="chip ${cls}" aria-pressed="${!!isOn(t)}" data-v="${esc(t)}">${esc(t)}</button>`).join('');
  el.onclick = e => { const b = e.target.closest('button'); if (!b) return; toggle(b.dataset.v); chips(el, list, isOn, toggle, cls); };
}
const toggleIn = (arr, v) => { const i = arr.indexOf(v); i >= 0 ? arr.splice(i, 1) : arr.push(v); };

/* ---------------- HOY ---------------- */
const SLIDERS = { en: [1, 5, '/5'], an: [1, 5, '/5'], fo: [1, 5, '/5'], su: [3, 12, ' h'], carga: [1, 5, '/5'], bat: [1, 5, '/5'] };
function paintSlider(box) {
  const k = box.dataset.k, inp = box.querySelector('input'), lab = box.querySelector('label span');
  const e = dayR(), v = box.dataset.s ? (e.sens || {})[k] : e[k];
  box.classList.toggle('unset', v == null);
  if (v != null) inp.value = v;
  lab.textContent = v == null ? 'sin dato' : (k === 'su' ? num(+v) : v) + SLIDERS[k][2];
}
$$('.slider[data-k]').forEach(box => {
  const inp = box.querySelector('input');
  const set = () => {
    const k = box.dataset.k, v = +inp.value, e = dayW();
    if (box.dataset.s) (e.sens ||= {})[k] = v; else e[k] = v;
    paintSlider(box); save();
  };
  inp.addEventListener('input', set); inp.addEventListener('change', set);
  inp.addEventListener('pointerdown', () => { if (box.classList.contains('unset')) setTimeout(set, 0); });
});

function banners() {
  const out = [], t = TODAY();
  const lb = META.lastBackup ? daysBetween(dkey(new Date(META.lastBackup)), t) : null;
  const any = Object.values(D.days).some(hasData);
  if (any && (lb == null || lb >= D.prefs.backupEvery))
    out.push(`<div class="banner ${lb == null || lb >= 14 ? 'red' : ''}"><span>${lb == null ? 'Aún no tienes copia de seguridad.' : `Tu última copia fue hace ${lb} días.`}</span><button class="btn primary" type="button" data-act="backup">Hacer copia</button></div>`);
  const ns = D.support.nextSession;
  if (ns && (ns === addDays(t, 1) || ns === t))
    out.push(`<div class="banner"><span>${ns === t ? 'Hoy' : 'Mañana'} tienes sesión. ¿Preparamos el informe?</span><button class="btn" type="button" data-go="informe">Informe</button></div>`);
  if (!D.prefs.welcomed)
    out.push(`<div class="banner"><span>Bienvenidx. Personaliza Hifa a tu medida.</span><button class="btn" type="button" data-act="welcome">Personalizar</button></div>`);
  else if (D.phrase && daysBetween(D.phrase.since, t) >= 90)
    out.push(`<div class="banner"><span>Pasaron 3 meses. ¿Elegimos una frase nueva?</span><button class="btn" type="button" data-act="frase">Elegir</button></div>`);
  return out.slice(0, 2).join('');
}
$('#banners').onclick = e => {
  const b = e.target.closest('[data-act]'); if (!b) return;
  if (b.dataset.act === 'backup') doBackup();
  if (b.dataset.act === 'welcome') { D.prefs.welcomed = true; save(); go('yo'); $('#personal').scrollIntoView({ block: 'start' }); }
  if (b.dataset.act === 'frase') { go('yo'); $('#frase').scrollIntoView({ block: 'start' }); }
};

function renderHoy() {
  const t = TODAY(), e = dayR();
  $('#today').textContent = new Date().toLocaleDateString('es-CO', { weekday: 'long', day: 'numeric', month: 'long' }).replace(/^./, c => c.toUpperCase());
  $('#banners').innerHTML = banners();
  $('#mood').innerHTML = [1, 2, 3, 4, 5].map(n => `<button type="button" aria-label="Ánimo ${n} de 5" aria-pressed="${e.mood === n}" data-m="${n}">${n}</button>`).join('');
  $$('.slider[data-k]').forEach(paintSlider);
  $('#sensoryCard').hidden = !D.prefs.sensory;
  if (D.prefs.sensory) {
    const s = e.sens || {};
    chips($('#satChips'), ['Ninguna', 'Saturación', 'Crisis (meltdown)', 'Desconexión (shutdown)'], v => ((dayR().sens || {}).sat || 'Ninguna') === v, v => { const w = dayW(); (w.sens ||= {}).sat = v; save(); $('#satBox').hidden = v === 'Ninguna'; });
    $('#satBox').hidden = !s.sat || s.sat === 'Ninguna';
    $('#satTrig').value = s.trig || ''; $('#satHelp').value = s.help || '';
  }
  $('#intakeCard').hidden = !D.prefs.showIntake;
  if (D.prefs.showIntake) paintIntake();
  renderQuote();
  const vis = D.habits.filter(h => !(h.food && tca())), done = D.hlog[t] || [];
  const on = vis.filter(h => done.includes(h.id));
  $('#habSum').textContent = `${on.length} de ${vis.length}` + (on.length ? ' · ' + on.slice(0, 3).map(h => h.n.split(' ')[0]).join(', ') : '');
  $('#habDots').innerHTML = vis.map(h => `<span class="${done.includes(h.id) ? 'on' : ''}"></span>`).join('');
  const month = t.slice(0, 7), nd = Object.entries(D.days).filter(([k, v]) => k.startsWith(month) && hasData(v)).length;
  $('#streak').textContent = nd ? `${nd} ${nd === 1 ? 'día hilado' : 'días hilados'} este mes` : '';
}
$('#mood').onclick = e => {
  const b = e.target.closest('button'); if (!b) return;
  const w = dayW(), n = +b.dataset.m; w.mood = w.mood === n ? undefined : n; if (w.mood === undefined) delete w.mood;
  vibrate(); save(); renderHoy();
};
['satTrig', 'satHelp'].forEach(id => $('#' + id).addEventListener('input', e => { const w = dayW(); (w.sens ||= {})[id === 'satTrig' ? 'trig' : 'help'] = e.target.value; save(); }));

/* ---- lo que tomé hoy ---- */
const CATS = {
  psilo: { label: 'Hongos psilocibios', color: 'var(--espora)', names: ['Golden Teacher', 'Rusty White', 'Blue Moon', 'Bluey Vuitton', 'B+', 'Penis Envy'], forms: ['Seco', 'Cápsula', 'Comestible', 'Té'] },
  funcional: { label: 'Hongos funcionales', color: 'var(--musgo)', names: ['Melena de león', 'Reishi', 'Cordyceps', 'Chaga', 'Cola de pavo'], forms: ['Cápsula', 'Polvo', 'Tintura', 'Té', 'Extracto'] },
  adapto: { label: 'Adaptógenos', color: 'var(--miel)', names: ['Ashwagandha', 'Rhodiola', 'Ginseng', 'Maca', 'Tulsi'], forms: ['Cápsula', 'Polvo', 'Tintura', 'Té', 'Extracto'] },
  supl: { label: 'Suplementos', color: 'var(--canela)', names: ['Magnesio', 'Omega 3', 'Vitamina D', 'Melatonina'], forms: ['Cápsula', 'Tableta', 'Polvo', 'Gotas'] },
  med: { label: 'Medicación', color: 'var(--amanita)', names: [], forms: ['Tableta', 'Cápsula', 'Gotas', 'Otro'] }
};
const F = { cat: 'psilo', name: 'Golden Teacher', dose: 'micro', form: 'Cápsula' };
const qtyText = it => it.form === 'Cápsula' ? `${it.capN || 1} cáps.` + (it.capMg ? ` × ${num(it.capMg)} mg = ${num(it.capN * it.capMg)} mg` : '') : (it.qty ? `${num(it.qty)} ${it.unit}` : '');
const itemDesc = it => [it.cat === 'psilo' ? (it.dose === 'macro' ? 'Macrodosis' : 'Microdosis') : CATS[it.cat].label, it.form, qtyText(it), it.time].filter(Boolean).join(' · ');
function paintIntake() {
  const list = dayR().intake || [];
  $('#routineBox').hidden = false;
  $('#routineDesc').textContent = D.routine.length ? D.routine.map(r => r.name + (r.cat === 'psilo' ? ` (${r.dose === 'macro' ? 'macro' : 'micro'})` : '')).join(' · ') : 'Registra lo que tomas y guárdalo como rutina para registrarlo con un toque.';
  const done = D.routine.length && list.some(i => i.fromRoutine);
  $('#routineBtn').hidden = !D.routine.length;
  $('#routineBtn').textContent = done ? 'Registrada ✓' : 'Registrar';
  $('#routineBtn').disabled = !!done;
  $('#intakeList').innerHTML = list.map((it, i) => `<div class="item"><span class="dot" style="background:${CATS[it.cat].color}"></span><span class="t">${esc(it.name)}<small>${esc(itemDesc(it))}</small></span><button type="button" aria-label="Quitar ${esc(it.name)}" data-i="${i}">×</button></div>`).join('');
  $('#intakeCount').textContent = list.length ? `${list.length} registrado${list.length > 1 ? 's' : ''}` : 'Nada registrado';
  $('#saveRoutineBtn').hidden = !list.length;
  $('#medCare').hidden = !(list.some(i => i.cat === 'med') && list.some(i => i.cat !== 'med'));
  $('#psyRisk').hidden = !(riskFlag() && list.some(i => i.cat === 'psilo'));
  const e = dayR();
  chips($('#effects'), ['Más claridad', 'Creatividad', 'Más calma', 'Más energía', 'Irritabilidad', 'Ansiedad', 'Malestar estomacal', 'Nada distinto'], v => (dayR().effects || []).includes(v), v => { const w = dayW(); toggleIn(w.effects ||= [], v); save(); });
}
$('#intakeList').onclick = e => { const b = e.target.closest('button'); if (!b) return; dayW().intake.splice(+b.dataset.i, 1); save(); paintIntake(); };
$('#routineBtn').onclick = () => { const w = dayW(); (w.intake ||= []).push(...D.routine.map(r => ({ ...r, fromRoutine: true }))); save(); paintIntake(); vibrate(); toast('Rutina registrada'); };
$('#saveRoutineBtn').onclick = () => { D.routine = (dayR().intake || []).map(({ fromRoutine, ...r }) => ({ ...r })); (dayW().intake || []).forEach(i => i.fromRoutine = true); save(); paintIntake(); toast('Guardado como tu rutina'); };
function paintForm() {
  const c = CATS[F.cat];
  $('#catChips').innerHTML = Object.entries(CATS).map(([k, v]) => `<button type="button" class="chip ${k === 'psilo' ? 'lav' : ''}" aria-pressed="${k === F.cat}" data-k="${k}">${v.label}</button>`).join('');
  $('#nameLabel').hidden = !c.names.length;
  $('#nameChips').innerHTML = c.names.map(n => `<button type="button" class="chip" aria-pressed="${n === F.name && !$('#itemName').value}" data-n="${esc(n)}">${esc(n)}</button>`).join('');
  $('#psiloDose').hidden = F.cat !== 'psilo';
  $$('#doseSeg button').forEach(x => x.setAttribute('aria-pressed', x.dataset.d === F.dose));
  $('#macroCare').hidden = !(F.cat === 'psilo' && F.dose === 'macro');
  if (!c.forms.includes(F.form)) F.form = c.forms[0];
  $('#formChips').innerHTML = c.forms.map(f => `<button type="button" class="chip" aria-pressed="${f === F.form}" data-f="${f}">${f}</button>`).join('');
  const cap = F.form === 'Cápsula'; $('#capRow').hidden = !cap; $('#qtyRow').hidden = cap; calcCap();
}
function calcCap() { const n = parseFloat($('#capN').value), mg = parseFloat($('#capMg').value); $('#capTotal').textContent = n && mg ? `Total: ${num(n * mg)} mg` : 'Escribe los mg por cápsula si los sabes'; }
$('#capN').oninput = calcCap; $('#capMg').oninput = calcCap;
$('#itemName').oninput = () => $$('#nameChips button').forEach(b => b.setAttribute('aria-pressed', 'false'));
$('#catChips').onclick = e => { const b = e.target.closest('button'); if (!b) return; F.cat = b.dataset.k; F.name = CATS[F.cat].names[0] || ''; $('#itemName').value = ''; paintForm(); };
$('#nameChips').onclick = e => { const b = e.target.closest('button'); if (!b) return; F.name = b.dataset.n; $('#itemName').value = ''; paintForm(); };
$('#formChips').onclick = e => { const b = e.target.closest('button'); if (!b) return; F.form = b.dataset.f; paintForm(); };
$('#doseSeg').onclick = e => { const b = e.target.closest('button'); if (!b) return; F.dose = b.dataset.d; paintForm(); };
$('#addItemBtn').onclick = () => { $('#itemForm').hidden = false; $('#addItemBtn').hidden = true; $('#itemTime').value = nowHM(); paintForm(); };
$('#cancelItem').onclick = () => { $('#itemForm').hidden = true; $('#addItemBtn').hidden = false; };
$('#saveItem').onclick = () => {
  const name = $('#itemName').value.trim() || F.name;
  if (!name) return toast('Escribe el nombre');
  const it = { cat: F.cat, name, form: F.form, time: $('#itemTime').value };
  if (F.cat === 'psilo') it.dose = F.dose;
  if (F.form === 'Cápsula') { it.capN = parseInt($('#capN').value) || 1; it.capMg = parseFloat($('#capMg').value) || null; }
  else { it.qty = parseFloat($('#itemQty').value) || null; it.unit = $('#itemUnit').value; }
  (dayW().intake ||= []).push(it); save();
  $('#itemForm').hidden = true; $('#addItemBtn').hidden = false; $('#itemQty').value = ''; $('#capMg').value = ''; $('#capN').value = '1'; $('#itemName').value = '';
  paintIntake(); toast('Agregado');
};

/* ---- frase del trimestre ---- */
const BANK = {
  cansancio: [['Pausar', 'Pauso antes de responder; mi ritmo también es productivo.'], ['Elegir', 'Elijo tres cosas al día, no treinta.'], ['Descansar', 'Descanso sin tener que ganármelo.']],
  ansiedad: [['Respirar', 'Respiro primero y decido después.'], ['Soltar', 'Suelto lo que no depende de mí y cuido lo que sí.'], ['Anclar', 'Me anclo en lo que tengo enfrente.']],
  tristeza: [['Agradecer', 'Agradezco lo pequeño que sí salió.'], ['Pedir', 'Pido ayuda; es de valientes.'], ['Acompañar', 'Me acompaño como acompañaría a alguien que quiero.']],
  motivacion: [['Crear', 'Creo algo cada día, aunque sea pequeño.'], ['Terminar', 'Termino lo que empiezo, una pieza a la vez.'], ['Explorar', 'Exploro con curiosidad, no con prisa.']]
};
const FEEL = { cansancio: 'Cansancio', ansiedad: 'Ansiedad', tristeza: 'Tristeza', motivacion: 'Con ganas' };
let feeling = 'cansancio', phraseIdx = 0;
function renderQuote() {
  const q = $('#quoteCard'), p = D.phrase;
  if (!p) { q.innerHTML = `<div class="eyebrow">Frase del trimestre</div><div>Elige una frase con un verbo para practicar estos meses.</div><button class="btn lav" type="button" data-act="frase">Elegir mi frase</button>`; q.onclick = e => { if (e.target.closest('[data-act]')) { go('yo'); $('#frase').scrollIntoView({ block: 'start' }); } }; return; }
  const wk = isoWeek(), done = !!(p.weeks || {})[wk];
  q.innerHTML = `<div class="eyebrow">Frase del trimestre · Verbo: ${esc(p.verb)}</div><q>${esc(p.text)}</q><label class="check muted"><input type="checkbox" id="qWeek" ${done ? 'checked' : ''}> Esta semana practiqué <b>${esc(p.verb.toLowerCase())}</b></label>`;
  q.onclick = null;
  $('#qWeek').onchange = e => { (D.phrase.weeks ||= {})[wk] = e.target.checked; if (!e.target.checked) delete D.phrase.weeks[wk]; save(); if (e.target.checked) { vibrate(); toast('¡Bien!'); } };
}
function renderPhrases() {
  chips($('#feelings'), Object.values(FEEL), v => FEEL[feeling] === v, v => { feeling = Object.keys(FEEL).find(k => FEEL[k] === v); phraseIdx = 0; renderPhrases(); }, 'lav');
  $('#phrases').innerHTML = BANK[feeling].map(([v, p], i) => `<button type="button" class="phrase" aria-pressed="${i === phraseIdx}" data-i="${i}"><em>VERBO: ${v.toUpperCase()}</em><span>“${p}”</span></button>`).join('');
}
$('#phrases').onclick = e => { const b = e.target.closest('.phrase'); if (b) { phraseIdx = +b.dataset.i; renderPhrases(); } };
$('#usePhrase').onclick = () => {
  const ov = $('#ownVerb').value.trim(), ot = $('#ownText').value.trim();
  const [verb, text] = ov && ot ? [ov, ot] : BANK[feeling][phraseIdx];
  D.phrase = { verb, text, since: TODAY(), weeks: {} }; save(); $('#ownVerb').value = $('#ownText').value = '';
  toast('Frase guardada para estos tres meses'); go('hoy');
};

/* ---------------- BITÁCORA ---------------- */
let jDay = TODAY();
const LEX = {
  st: { trabajo: 'Trabajo', jefe: 'Trabajo', oficina: 'Trabajo', informe: 'Trabajo', reunión: 'Trabajo', herman: 'Familia', mamá: 'Familia', papá: 'Familia', familia: 'Familia', pareja: 'Pareja', novi: 'Pareja', dormí: 'Sueño', sueño: 'Sueño', insomnio: 'Sueño', plata: 'Dinero', dinero: 'Dinero', deuda: 'Dinero', salud: 'Salud', dolor: 'Salud', ruido: 'Sensorial', tráfico: 'Ciudad', estudio: 'Estudio', universidad: 'Estudio', examen: 'Estudio' },
  ok: { terminé: 'Logro', logré: 'Logro', avancé: 'Logro', caminé: 'Movimiento', ejercicio: 'Movimiento', medité: 'Calma', tranquil: 'Calma', feliz: 'Ánimo alto', contenta: 'Ánimo alto', contento: 'Ánimo alto', amig: 'Conexión', creé: 'Creatividad', escribí: 'Creatividad' }
};
const RISK = /no quiero vivir|quiero morir|matarme|suicid|hacerme daño|lastimarme|quitarme la vida|no vale la pena vivir/;
const GUIDE = ['¿Qué fue lo más importante de tu día?', '¿Qué te dio energía hoy?', '¿Qué te la quitó?', '¿Hubo algo que quieras llevar a tu próxima sesión?', '¿Cómo está tu cuerpo ahora mismo?', '¿Qué agradeces de hoy, aunque sea pequeño?'];
const GUIDE_LIT = ['Del 1 al 5, ¿cuál fue tu nivel de energía hoy?', '¿Qué actividad hiciste que te gustó?', '¿Qué actividad te cansó?', '¿Quieres llevar algún tema a tu próxima sesión? Escríbelo.', '¿Dormiste bien? Responde sí o no.', 'Escribe una cosa que salió bien hoy.'];
function extractTags(text) {
  const low = text.toLowerCase(), st = new Set(), ok = new Set();
  for (const [k, v] of Object.entries(LEX.st)) if (low.includes(k)) st.add(v);
  for (const [k, v] of Object.entries(LEX.ok)) if (low.includes(k)) ok.add(v);
  return { st: [...st], ok: [...ok] };
}
function renderChat() {
  $('#jDate').max = TODAY(); $('#jDate').value = jDay;
  const e = dayR(jDay), J = e.journal || [];
  let h = '';
  if (!J.length) h += `<div class="msg ai">${jDay === TODAY() ? (D.prefs.literal ? 'Escribe qué pasó hoy. Puedes usar frases cortas.' : 'Hola. ¿Qué fue lo más importante de tu día? Cuéntalo como salga.') : 'No hay bitácora para este día. Puedes escribirla ahora.'}</div>`;
  h += J.map(m => `<div class="msg ${m.w === 'me' ? 'me' : 'ai'}">${esc(m.t).replace(/\n/g, '<br>')}${m.w === 'me' && m.at ? `<div class="muted small">${new Date(m.at).toTimeString().slice(0, 5)}</div>` : ''}</div>`).join('');
  const tg = e.tags || { st: [], ok: [] };
  if (tg.st.length || tg.ok.length) h += `<div class="msg sum"><div class="muted small" style="font-weight:600">LO QUE ENTENDÍ DE ESTE DÍA</div>${tg.st.map(v => `<span class="tag st">Estresor: ${esc(v)}</span>`).join('')}${tg.ok.map(v => `<span class="tag ok">${esc(v)}</span>`).join('')}</div>`;
  $('#chat').innerHTML = h;
  chips($('#prompts'), ['Algo bueno de hoy', 'Me estresó…', 'Efecto que noté', 'Para mi sesión:'], () => false, t => { $('#msgIn').value = t + ' '; $('#msgIn').focus(); });
}
$('#jDate').onchange = e => { if (e.target.value && e.target.value <= TODAY()) { jDay = e.target.value; renderChat(); } };
function send() {
  const t = $('#msgIn').value.trim(); if (!t) return;
  stopRec();
  const e = dayW(jDay), J = (e.journal ||= []);
  J.push({ w: 'me', t, at: new Date().toISOString() });
  const tg = extractTags(t), cur = (e.tags ||= { st: [], ok: [] });
  tg.st.forEach(v => !cur.st.includes(v) && cur.st.push(v)); tg.ok.forEach(v => !cur.ok.includes(v) && cur.ok.push(v));
  let r;
  if (RISK.test(t.toLowerCase())) { r = 'Gracias por contármelo. Lo que sientes importa y no tienes que pasarlo solx. Si estás en peligro ahora, llama al 123 o a la Línea 192, opción 4. También puedes escribirle a tu psicólogx.'; setTimeout(openHelp, 400); }
  else if (tg.st.length) r = D.prefs.literal ? 'Entendido. Del 1 al 5, ¿qué tan fuerte fue ese estrés?' : 'Eso suena pesado. ¿Cómo te sentiste después?';
  else { const n = J.filter(m => m.w === 'me').length; r = (D.prefs.literal ? GUIDE_LIT : GUIDE)[n % GUIDE.length]; }
  J.push({ w: 'hifa', t: r });
  $('#msgIn').value = ''; save(); renderChat();
  $('#chat').lastElementChild?.scrollIntoView({ block: 'end', behavior: D.prefs.noanim ? 'auto' : 'smooth' });
}
$('#send').onclick = send;
$('#msgIn').addEventListener('keydown', e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); send(); } });
/* dictado por voz (si el navegador lo permite) */
const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
let rec = null;
function stopRec() { if (rec) { try { rec.stop(); } catch (e) {} rec = null; $('#rec').classList.remove('on'); $('#rec').setAttribute('aria-label', 'Dictar por voz'); } }
$('#rec').onclick = () => {
  if (rec) return stopRec();
  if (!SR) return toast('Usa el micrófono de tu teclado para dictar');
  rec = new SR(); rec.lang = 'es-CO'; rec.interimResults = true; rec.continuous = true;
  const base = $('#msgIn').value ? $('#msgIn').value.trim() + ' ' : '';
  rec.onresult = ev => { let s = ''; for (const r of ev.results) s += r[0].transcript; $('#msgIn').value = base + s; };
  rec.onerror = ev => { toast(ev.error === 'not-allowed' ? 'Permite el micrófono para dictar' : 'No se pudo dictar; usa el teclado'); stopRec(); };
  rec.onend = () => { if (rec) stopRec(); };
  try { rec.start(); $('#rec').classList.add('on'); $('#rec').setAttribute('aria-label', 'Detener dictado'); toast('Escuchando… toca de nuevo para parar'); } catch (e) { stopRec(); }
};

/* ---------------- PANEL ---------------- */
let range = 30;
$('#range').onclick = e => { const b = e.target.closest('button'); if (!b) return; range = +b.dataset.d; $$('#range button').forEach(x => x.setAttribute('aria-pressed', x === b)); renderPanel(); };
function rangeKeys(n, end = TODAY()) { const out = []; for (let i = n - 1; i >= 0; i--) out.push(addDays(end, -i)); return out; }
const psiloOf = e => (e.intake || []).filter(i => i.cat === 'psilo');
function lowRun(keys, get = dayR) {
  let best = null, cur = 0, start = 0;
  keys.forEach((k, i) => { const m = get(k).mood; if (m == null) return; if (m <= 2) { if (!cur) start = i; cur++; if (cur >= 5 && (!best || cur > best.len)) best = { start, end: i, len: cur }; } else cur = 0; });
  return best;
}
function chartSVG(get, keys) {
  const moods = keys.map(k => get(k).mood ?? null);
  const W = 340, H = 150, pl = 24, pr = 8, pt = 8, pb = 30, n = keys.length;
  const rr = n > 40 ? 2 : 3, x = i => pl + (W - pl - pr) * (n === 1 ? 0 : i / (n - 1)), y = m => pt + (H - pt - pb) * (5 - m) / 4;
  let g = ''; [1, 2, 3, 4, 5].forEach(m => g += `<line x1="${pl}" x2="${W - pr}" y1="${y(m)}" y2="${y(m)}" style="stroke:var(--line)"/><text x="${pl - 8}" y="${y(m) + 4}" font-size="10" text-anchor="end" style="fill:var(--muted)">${m}</text>`);
  const run = lowRun(keys, get);
  if (run) g += `<rect x="${x(run.start) - 3}" y="${pt}" width="${Math.max(6, x(run.end) - x(run.start) + 6)}" height="${H - pt - pb}" style="fill:var(--amanita-soft)"/>`;
  let seg = [], segs = [];
  moods.forEach((m, i) => { if (m == null) { if (seg.length) segs.push(seg); seg = []; } else seg.push(`${x(i)},${y(m)}`); });
  if (seg.length) segs.push(seg);
  segs.forEach(sg => { if (sg.length > 1) g += `<polyline points="${sg.join(' ')}" style="fill:none;stroke:var(--musgo)" stroke-width="2.4" stroke-linejoin="round" stroke-linecap="round"/>`; });
  moods.forEach((m, i) => { if (m != null) g += `<circle cx="${x(i)}" cy="${y(m)}" r="${rr}" style="fill:var(--musgo)"/>`; });
  keys.forEach((k, i) => { const ps = psiloOf(get(k)); if (!ps.length) return; g += ps.some(p => p.dose === 'macro') ? `<circle cx="${x(i)}" cy="${H - pb + 10}" r="4" style="fill:var(--card);stroke:var(--espora)" stroke-width="2.2"/>` : `<circle cx="${x(i)}" cy="${H - pb + 10}" r="3.2" style="fill:var(--espora)"/>`; });
  g += `<text x="${pl}" y="${H - 2}" font-size="10" style="fill:var(--muted)">${fmtD(keys[0])}</text><text x="${W - pr}" y="${H - 2}" font-size="10" text-anchor="end" style="fill:var(--muted)">${keys[n - 1] === TODAY() ? 'Hoy' : fmtD(keys[n - 1])}</text>`;
  const withM = moods.filter(m => m != null);
  return { svg: g, run, avg: withM.length ? withM.reduce((a, b) => a + b, 0) / withM.length : null, count: withM.length };
}
const avg = a => a.length ? a.reduce((s, x) => s + x, 0) / a.length : null;
const BANDS = { PHQ9: [[4, 'mínimo'], [9, 'leve'], [14, 'moderado'], [19, 'moderadamente severo'], [27, 'severo']], GAD7: [[4, 'mínimo'], [9, 'leve'], [14, 'moderado'], [21, 'severo']] };
const band = (type, s) => BANDS[type].find(([m]) => s <= m)[1];
function renderPanel() {
  applyPrefs();
  const keys = rangeKeys(range), moods = keys.map(k => dayR(k).mood ?? null), reg = keys.filter(k => hasData(dayR(k)));
  const withM = moods.filter(m => m != null);
  $('#panelEmpty').hidden = withM.length >= 2;
  $('#chartCard').hidden = withM.length < 2;
  // gráfico
  if (withM.length >= 2) {
    const c = chartSVG(dayR, keys), run = c.run, a = c.avg;
    $('#chart').innerHTML = c.svg;
    const prev = rangeKeys(range, addDays(TODAY(), -range)).map(k => dayR(k).mood).filter(m => m != null), p = avg(prev);
    $('#avg').textContent = `promedio ${num(a)}` + (p != null && prev.length >= 2 ? ` · ${a >= p ? '↑' : '↓'} ${num(Math.abs(a - p))}` : '');
    $('#alertBox').innerHTML = run ? `<div class="alert"><div><b>Un patrón que vale la pena hablar</b><p>Del ${fmtD(keys[run.start])} al ${fmtD(keys[run.end])} tu ánimo estuvo en 1–2 durante ${run.len} días registrados seguidos. Puede ayudar comentarlo con tu psicólogx.</p></div></div>` : '';
  } else $('#alertBox').innerHTML = '';
  $('#kDays').innerHTML = `${reg.length} <small>de ${keys.length}</small>`;
  $('#kAvg').textContent = num(avg(withM));
  const wi = keys.filter(k => psiloOf(dayR(k)).length && dayR(k).mood != null).map(k => dayR(k).mood);
  const wo = keys.filter(k => !psiloOf(dayR(k)).length && dayR(k).mood != null).map(k => dayR(k).mood);
  $('#kWith').innerHTML = wi.length >= 3 ? `${num(avg(wi))} <small>${wi.length} días</small>` : '<small>faltan datos</small>';
  $('#kWithout').innerHTML = wo.length >= 3 ? `${num(avg(wo))} <small>${wo.length} días</small>` : '<small>faltan datos</small>';
  // escalas
  const last = t => D.scales.filter(s => s.type === t).sort((a, b) => a.date < b.date ? 1 : -1);
  const row = (t, name) => { const l = last(t), s = l[0], pv = l[1];
    return `<div class="scrow"><div><div style="font-weight:600">${name}</div><div class="muted small">${s ? `${band(t, s.score)} · ${fmtD(s.date)}${pv ? ` · antes ${pv.score}` : ''}` : 'Sin responder'}</div></div>${s ? `<b>${s.score}</b>` : ''}<button class="btn small" type="button" data-scale="${t}">${s ? 'Repetir' : 'Responder'}</button></div>`; };
  const lastAny = D.scales.map(s => s.date).sort().pop();
  $('#scalesCard').innerHTML = `<h2>Escalas</h2>${row('PHQ9', 'PHQ-9 · ánimo')}${row('GAD7', 'GAD-7 · ansiedad')}<p class="muted small">${lastAny && daysBetween(lastAny, TODAY()) < 14 ? 'Se recomienda responderlas cada 2 semanas.' : 'Es buen momento para responderlas (cada 2 semanas).'}</p>`;
  // estresores
  const cnt = {}; keys.forEach(k => (dayR(k).tags?.st || []).forEach(v => cnt[v] = (cnt[v] || 0) + 1));
  const top = Object.entries(cnt).sort((a, b) => b[1] - a[1]).slice(0, 5), mx = top.length ? top[0][1] : 1;
  $('#stress').innerHTML = top.map(([n, c]) => `<span>${esc(n)}</span><i style="width:${c / mx * 100}%"></i><span class="muted">${c}</span>`).join('');
  $('#stressEmpty').hidden = !!top.length;
  // sensorial
  const sat = keys.map(k => dayR(k).sens).filter(s => s && s.sat && s.sat !== 'Ninguna');
  $('#sensPanel').hidden = !D.prefs.sensory || !sat.length;
  if (sat.length) { const tr = sat.map(s => s.trig).filter(Boolean), hl = sat.map(s => s.help).filter(Boolean);
    $('#sensSum').innerHTML = `${sat.length} ${sat.length === 1 ? 'episodio' : 'episodios'} de saturación.${tr.length ? `<br>Detonantes: ${esc(tr.slice(-3).join('; '))}` : ''}${hl.length ? `<br>Lo que ayudó: ${esc(hl.slice(-3).join('; '))}` : ''}`; }
  // correlación de hábitos
  let best = null;
  D.habits.filter(h => !(h.food && tca())).forEach(h => {
    const yes = [], no = []; keys.forEach(k => { const m = dayR(k).mood; if (m == null) return; ((D.hlog[k] || []).includes(h.id) ? yes : no).push(m); });
    if (yes.length >= 5 && no.length >= 5) { const d = avg(yes) - avg(no); if (!best || Math.abs(d) > Math.abs(best.d)) best = { h, d }; }
  });
  $('#corrNote').hidden = !best || Math.abs(best.d) < 0.3;
  if (best) $('#corrNote').innerHTML = `<b>Patrón:</b> los días que marcaste «${esc(best.h.n)}», tu ánimo fue ${num(Math.abs(best.d))} puntos ${best.d > 0 ? 'más alto' : 'más bajo'} en promedio (observacional).`;
}
$('#scalesCard').onclick = e => { const b = e.target.closest('[data-scale]'); if (b) openScale(b.dataset.scale); };

/* ---------------- ESCALAS ---------------- */
const SCALES = {
  PHQ9: { title: 'PHQ-9 · ánimo', items: ['Poco interés o placer en hacer cosas', 'Se ha sentido decaído(a), deprimido(a) o sin esperanzas', 'Ha tenido dificultad para quedarse o permanecer dormido(a), o ha dormido demasiado', 'Se ha sentido cansado(a) o con poca energía', 'Sin apetito o ha comido en exceso', 'Se ha sentido mal con usted mismo(a), o que es un fracaso, o que ha quedado mal con usted mismo(a) o con su familia', 'Ha tenido dificultad para concentrarse en ciertas actividades, tales como leer o ver televisión', '¿Se ha movido o hablado tan lento que otras personas podrían haberlo notado? O lo contrario: muy inquieto(a) o agitado(a), moviéndose mucho más de lo normal', 'Pensamientos de que estaría mejor muerto(a) o de lastimarse de alguna manera'] },
  GAD7: { title: 'GAD-7 · ansiedad', items: ['Se ha sentido nervioso(a), ansioso(a) o con los nervios de punta', 'No ha sido capaz de parar o controlar su preocupación', 'Se ha preocupado demasiado por motivos diferentes', 'Ha tenido dificultad para relajarse', 'Se ha sentido tan inquieto(a) que no ha podido quedarse quieto(a)', 'Se ha molestado o irritado fácilmente', 'Ha tenido miedo de que algo terrible fuera a pasar'] }
};
const OPTS = ['Ningún día', 'Varios días', 'Más de la mitad de los días', 'Casi todos los días'];
let scType = null, scAns = [];
function openScale(t) {
  scType = t; scAns = new Array(SCALES[t].items.length).fill(null);
  $('#scTitle').textContent = SCALES[t].title;
  $('#scIntro').textContent = 'Durante las últimas 2 semanas, ¿qué tan seguido le han afectado los siguientes problemas?';
  $('#scResult').innerHTML = ''; $('#scSave').hidden = false;
  paintScale(); go('escala');
}
function paintScale() {
  $('#scQs').innerHTML = SCALES[scType].items.map((q, i) => `<div class="scq"><p>${i + 1}. ${q}</p><div class="scopts" data-q="${i}">${OPTS.map((o, v) => `<button type="button" aria-pressed="${scAns[i] === v}" data-v="${v}">${o}</button>`).join('')}</div></div>`).join('');
}
$('#scQs').onclick = e => { const b = e.target.closest('button'); if (!b) return; const q = +b.closest('[data-q]').dataset.q; scAns[q] = +b.dataset.v; b.parentElement.querySelectorAll('button').forEach(x => x.setAttribute('aria-pressed', x === b)); };
$('#scSave').onclick = () => {
  const miss = scAns.findIndex(a => a == null);
  if (miss >= 0) { toast(`Falta la pregunta ${miss + 1}`); $$('.scq')[miss].scrollIntoView({ block: 'center' }); return; }
  const score = scAns.reduce((s, x) => s + x, 0);
  D.scales.push({ type: scType, date: TODAY(), answers: [...scAns], score }); save();
  const crisis = scType === 'PHQ9' && scAns[8] > 0;
  $('#scResult').innerHTML = `<div class="card"><h2>Resultado: ${score} · ${band(scType, score)}</h2><p class="muted">Guardado en tu panel e informe. Es un tamizaje, no un diagnóstico: coméntalo con tu psicólogx.</p>${crisis ? `<div class="care"><b>Sobre la pregunta 9</b> Marcaste pensamientos de muerte o de hacerte daño. No tienes que pasarlo solx: habla hoy con alguien de confianza o con tu psicólogx. Si estás en peligro: 123 o Línea 192, opción 4.</div>` : ''}<button class="btn primary" type="button" data-go="panel">Volver al panel</button></div>`;
  $('#scSave').hidden = true; $('#scResult').scrollIntoView({ block: 'start' });
  if (crisis) setTimeout(openHelp, 500);
};

/* ---------------- HÁBITOS ---------------- */
let editing = false;
function renderHabits() {
  const t = TODAY(), done = D.hlog[t] || [], last30 = rangeKeys(30);
  const vis = D.habits.filter(h => !(h.food && tca()));
  $('#habits').innerHTML = vis.map(h => {
    const on = done.includes(h.id), c = last30.filter(k => (D.hlog[k] || []).includes(h.id)).length;
    return `<div class="habit" role="button" tabindex="0" aria-pressed="${on}" data-id="${h.id}"><span class="ck">${on ? '<svg class="i" viewBox="0 0 24 24" style="width:18px;height:18px;stroke-width:2.5"><path d="M20 6 9 17l-5-5"/></svg>' : ''}</span><span><b>${esc(h.n)}</b><span class="muted">${c} de 30 días</span></span>${editing ? `<button class="x" type="button" aria-label="Eliminar ${esc(h.n)}" data-del="${h.id}">×</button>` : ''}</div>`;
  }).join('') || '<p class="muted">Agrega tu primer hábito abajo.</p>';
  $('#editHab').textContent = editing ? 'Listo' : 'Editar';
  const n = $('#habNote'); n.hidden = !tca(); n.innerHTML = '<b>Modo cuidado con la comida:</b> los hábitos de comida están ocultos.';
}
function toggleHabit(id) { const t = TODAY(), a = (D.hlog[t] ||= []); toggleIn(a, id); if (!a.length) delete D.hlog[t]; save(); vibrate(); renderHabits(); if (a.includes(id)) toast('¡Un paso más!'); }
$('#habits').onclick = e => {
  const del = e.target.closest('[data-del]');
  if (del) { const h = D.habits.find(x => x.id === del.dataset.del); if (confirm(`¿Eliminar «${h.n}»? Se conserva lo ya registrado en el informe.`)) { D.habits = D.habits.filter(x => x.id !== h.id); save(); renderHabits(); } return; }
  const b = e.target.closest('.habit'); if (b && !editing) toggleHabit(b.dataset.id);
};
$('#habits').onkeydown = e => { if ((e.key === 'Enter' || e.key === ' ') && e.target.classList.contains('habit') && !editing) { e.preventDefault(); toggleHabit(e.target.dataset.id); } };
$('#editHab').onclick = () => { editing = !editing; renderHabits(); };
$('#addHab').onclick = () => { const v = $('#newHab').value.trim(); if (!v) return; D.habits.push({ id: uid(), n: v }); $('#newHab').value = ''; save(); renderHabits(); };

/* ---------------- YO ---------------- */
function renderYo() {
  $('#compass').value = D.purpose.compass || '';
  chips($('#values'), D.purpose.values, v => D.purpose.valuesOn.includes(v), v => { toggleIn(D.purpose.valuesOn, v); save(); }, 'lav');
  renderPhrases();
  chips($('#minds'), MINDS, v => D.prefs.minds.includes(v), v => {
    toggleIn(D.prefs.minds, v);
    if (v === 'Autismo' && D.prefs.minds.includes(v)) { D.prefs.sensory = true; D.prefs.literal = true; toast('Activamos registro sensorial y lenguaje literal. Puedes apagarlos.'); }
    D.prefs.welcomed = true; save(); renderYo();
  });
  Object.entries(GROUPS).forEach(([id, list]) => chips($('#' + id), list, v => D.prefs.goals.includes(v), v => { toggleIn(D.prefs.goals, v); D.prefs.welcomed = true; save(); renderYoNotes(); }));
  renderYoNotes();
  $$('[data-pref]').forEach(i => i.checked = !!D.prefs[i.dataset.pref]);
  $$('#themeSeg button').forEach(b => b.setAttribute('aria-pressed', b.dataset.t === D.prefs.theme));
  $$('#viewSeg button').forEach(b => b.setAttribute('aria-pressed', b.dataset.v === D.prefs.view));
  $$('#bkEvery button').forEach(b => b.setAttribute('aria-pressed', +b.dataset.n === D.prefs.backupEvery));
  $('#psyName').value = D.support.psyName; $('#psyPhone').value = D.support.psyPhone; $('#nextSession').value = D.support.nextSession;
  $('#supportLinks').innerHTML = helpLinks();
  renderLink();
  renderBackupState();
}
function renderYoNotes() { $('#riskNote').hidden = !riskFlag(); $('#tcaNote').hidden = !tca(); }
let compT; $('#compass').oninput = e => { clearTimeout(compT); compT = setTimeout(() => { D.purpose.compass = e.target.value; save(); }, 400); };
$('#addVal').onclick = () => { const v = $('#newVal').value.trim(); if (!v || D.purpose.values.includes(v)) return; D.purpose.values.push(v); D.purpose.valuesOn.push(v); $('#newVal').value = ''; save(); renderYo(); };
$$('[data-pref]').forEach(i => i.onchange = () => { D.prefs[i.dataset.pref] = i.checked; D.prefs.welcomed = true; save(); applyPrefs(); });
$('#themeSeg').onclick = e => { const b = e.target.closest('button'); if (!b) return; D.prefs.theme = b.dataset.t; save(); applyPrefs(); renderYo(); };
$('#viewSeg').onclick = e => { const b = e.target.closest('button'); if (!b) return; D.prefs.view = b.dataset.v; save(); applyPrefs(); renderYo(); };
$('#bkEvery').onclick = e => { const b = e.target.closest('button'); if (!b) return; D.prefs.backupEvery = +b.dataset.n; save(); renderYo(); };
[['psyName', 'psyName'], ['psyPhone', 'psyPhone'], ['nextSession', 'nextSession']].forEach(([id, k]) => $('#' + id).addEventListener('change', e => { D.support[k] = e.target.value; save(); $('#supportLinks').innerHTML = helpLinks(); }));

/* ---------------- COPIAS DE SEGURIDAD ---------------- */
function renderBackupState() {
  const lb = META.lastBackup, d = lb ? daysBetween(dkey(new Date(lb)), TODAY()) : null;
  const el = $('#backupState');
  el.className = 'bstate' + (d == null || d >= D.prefs.backupEvery ? ' late' : '');
  el.innerHTML = lb ? `<b>Última copia: ${d === 0 ? 'hoy' : d === 1 ? 'ayer' : `hace ${d} días`}</b>${new Date(lb).toLocaleString('es-CO', { dateStyle: 'medium', timeStyle: 'short' })}` : '<b>Aún no tienes copia</b>Haz una y guárdala fuera de este dispositivo (Drive, iCloud, correo o computador).';
  if (navigator.storage && navigator.storage.persisted) navigator.storage.persisted().then(p => $('#persistState').textContent = p ? 'El navegador protege tus datos contra borrado automático.' : 'Consejo: instala Hifa en tu pantalla de inicio para que el navegador no borre los datos.');
}
async function doBackup() {
  try {
    await saveChain;
    const env = { ...(await seal(D)), exportedAt: new Date().toISOString() };
    const name = `hifa-copia-${TODAY()}.json`, body = JSON.stringify(env);
    let shared = false;
    const mobile = /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
    if (mobile && navigator.canShare) {
      for (const type of ['application/json', 'text/plain']) {
        const file = new File([body], name, { type });
        if (navigator.canShare({ files: [file] })) {
          try { await navigator.share({ files: [file], title: 'Copia de Hifa' }); shared = true; }
          catch (e) { if (e.name === 'AbortError') return toast('Copia cancelada'); }
          break;
        }
      }
    }
    if (!shared) { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([body], { type: 'application/json' })); a.download = name; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 4000); }
    await setMeta({ lastBackup: new Date().toISOString() });
    toast('Copia lista. Guárdala fuera de este dispositivo.');
    renderBackupState(); if (!isPro()) renderHoy();
  } catch (e) { console.error(e); toast('No se pudo crear la copia'); }
}
$('#doBackup').onclick = doBackup;
$('#restoreBtn').onclick = () => $('#restoreFile').click();
$('#restoreFile').onchange = async e => {
  const f = e.target.files[0]; e.target.value = ''; if (!f) return;
  let env; try { env = JSON.parse(await f.text()); } catch (er) { return toast('Ese archivo no es una copia de Hifa'); }
  if (!validEnvelope(env)) return toast('Ese archivo no es una copia de Hifa');
  const p = await askPass('Escribe la clave con la que se creó esa copia.'); if (!p) return;
  toast('Abriendo copia…');
  try {
    const data = migrate(await unseal(env, await deriveKey(p, unb64(env.kdf.salt), env.kdf.iterations || ITER)));
    const nd = data.role === 'pro' ? Object.keys(data.patients || {}).length : Object.values(data.days).filter(hasData).length;
    if (!confirm(`La copia tiene ${nd} ${data.role === 'pro' ? 'pacientes' : 'días registrados'}${env.exportedAt ? ` (del ${new Date(env.exportedAt).toLocaleDateString('es-CO')})` : ''}. Reemplazará lo que hay ahora en este dispositivo. ¿Continuar?`)) return;
    if ((data.role === 'pro') !== isPro()) return toast(isPro() ? 'Esa copia es de una cuenta personal, no profesional' : 'Esa copia es de una cuenta profesional');
    D = data; await save(true); applyPrefs(); renderAll(); toast('Copia restaurada');
  } catch (er) { toast('Clave incorrecta para esa copia'); }
};
/* copia automática en archivo (solo navegadores de computador que lo permiten) */
let fileHandle = null, fileT = null;
async function initFileBackup() {
  if (!window.showSaveFilePicker) return;
  $('#fsBox').hidden = false;
  fileHandle = await DB.get('fileHandle') || null;
  paintFs();
}
async function paintFs() {
  if (!fileHandle) { $('#fsState').textContent = 'Desactivada.'; $('#fsOff').hidden = true; $('#fsPick').textContent = 'Elegir archivo'; return; }
  const perm = await fileHandle.queryPermission({ mode: 'readwrite' }).catch(() => 'denied');
  $('#fsOff').hidden = false;
  $('#fsPick').textContent = perm === 'granted' ? 'Cambiar archivo' : 'Reconectar archivo';
  $('#fsState').textContent = perm === 'granted' ? `Activa: se actualiza «${fileHandle.name}» cada vez que guardas.` : `Toca «Reconectar archivo» para seguir actualizando «${fileHandle.name}».`;
}
function scheduleFileWrite(env) {
  if (!fileHandle) return; clearTimeout(fileT);
  fileT = setTimeout(async () => {
    try {
      if (await fileHandle.queryPermission({ mode: 'readwrite' }) !== 'granted') return;
      const w = await fileHandle.createWritable(); await w.write(JSON.stringify({ ...env, exportedAt: new Date().toISOString() })); await w.close();
      await setMeta({ lastBackup: new Date().toISOString() });
    } catch (e) { console.warn(e); }
  }, 2500);
}
$('#fsPick').onclick = async () => {
  try {
    if (fileHandle && await fileHandle.queryPermission({ mode: 'readwrite' }) === 'prompt') { await fileHandle.requestPermission({ mode: 'readwrite' }); }
    else { fileHandle = await window.showSaveFilePicker({ suggestedName: 'hifa-mi-bitacora.json', types: [{ description: 'Copia de Hifa', accept: { 'application/json': ['.json'] } }] }); await DB.set('fileHandle', fileHandle); }
    paintFs(); save(); toast('Copia automática activa');
  } catch (e) { if (e.name !== 'AbortError') toast('No se pudo usar ese archivo'); }
};
$('#fsOff').onclick = async () => { fileHandle = null; await DB.del('fileHandle'); paintFs(); };

/* recordatorios en el calendario (.ics) */
function ics(summary, desc, rrule, hhmm, dayOffset = 0) {
  const d = new Date(); d.setDate(d.getDate() + dayOffset);
  const [h, m] = hhmm.split(':');
  const dt = `${dkey(d).replace(/-/g, '')}T${h}${m}00`;
  const stamp = new Date().toISOString().replace(/[-:]/g, '').slice(0, 15) + 'Z';
  return ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//Hifa//ES', 'CALSCALE:GREGORIAN', 'BEGIN:VEVENT', `UID:${uid()}-${Date.now()}@hifa.local`, `DTSTAMP:${stamp}`, `DTSTART:${dt}`, 'DURATION:PT10M', `RRULE:${rrule}`, `SUMMARY:${summary}`, `DESCRIPTION:${desc}`, 'BEGIN:VALARM', 'ACTION:DISPLAY', `DESCRIPTION:${summary}`, 'TRIGGER:PT0M', 'END:VALARM', 'END:VEVENT', 'END:VCALENDAR'].join('\r\n');
}
function downloadIcs(name, text) {
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type: 'text/calendar' })); a.download = name;
  document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  toast('Abre el archivo para agregarlo a tu calendario');
}
$('#icsBackup').onclick = () => { const dow = new Date().getDay(), off = (7 - dow) % 7; downloadIcs('hifa-copia-semanal.ics', ics('Hifa: hacer copia de seguridad', 'Abre Hifa > Yo > Hacer copia ahora.', 'FREQ=WEEKLY;BYDAY=SU', '19:00', off)); };
$('#icsDaily').onclick = () => downloadIcs('hifa-registro-diario.ics', ics('Hifa: ¿cómo estás hoy?', 'Registrarlo te toma 30 segundos.', 'FREQ=DAILY', $('#icsTime').value || '20:00'));

/* seguridad */
$('#lockNow').onclick = lockNow;
$('#changePass').onclick = async () => {
  const p = await askPass('Escribe tu nueva clave (mínimo 8 caracteres). Las copias viejas seguirán abriéndose con su clave anterior.', true);
  if (!p) return; if (p.length < 8) return toast('Mínimo 8 caracteres');
  SALT = crypto.getRandomValues(new Uint8Array(16)); KEY = await deriveKey(p, SALT); await save(true);
  toast('Clave cambiada. Haz una copia nueva.');
};
$('#wipeAll').onclick = async () => {
  const w = prompt('Esto borra todos tus datos de Hifa en este dispositivo. Escribe BORRAR para confirmar.');
  if ((w || '').trim().toUpperCase() !== 'BORRAR') return;
  await DB.clear(); location.reload();
};

/* ---------------- INFORME ---------------- */
function reportText(src, keys, includeJournal) {
  const get = src.get, from = keys[0], to = keys[keys.length - 1];
  const reg = keys.filter(k => hasData(get(k))), moods = keys.map(k => get(k).mood).filter(m => m != null);
  const run = lowRun(keys, get);
  const pick = t => (src.scales || []).filter(s => s.type === t && s.date >= from && s.date <= to).sort((a, b) => a.date < b.date ? -1 : 1);
  const scLine = (t, n) => { const l = pick(t); return l.length ? `${n}: ${l.map(s => `${s.score} (${band(t, s.score)}, ${fmtD(s.date)})`).join(' → ')}` : `${n}: sin respuestas en el periodo`; };
  const sub = {}; keys.forEach(k => (get(k).intake || []).forEach(it => {
    const x = (sub[it.name] ||= { cat: it.cat, days: new Set(), micro: 0, macro: 0, q: [] });
    x.days.add(k); if (it.cat === 'psilo') it.dose === 'macro' ? x.macro++ : x.micro++; const q = qtyText(it); if (q) x.q.push(q);
  }));
  const subLines = Object.entries(sub).sort((a, b) => b[1].days.size - a[1].days.size).map(([n, x]) => {
    const qs = [...new Set(x.q)].slice(0, 3).join('; ');
    return `• ${n} (${(CATS[x.cat] || { label: x.cat }).label.toLowerCase()}): ${x.days.size} ${x.days.size === 1 ? 'día' : 'días'}${x.cat === 'psilo' ? ` · ${x.micro} micro, ${x.macro} macro` : ''}${qs ? ` · ${qs}` : ''}`;
  });
  const eff = {}; keys.forEach(k => (get(k).effects || []).forEach(v => eff[v] = (eff[v] || 0) + 1));
  const st = {}; keys.forEach(k => (get(k).tags?.st || []).forEach(v => st[v] = (st[v] || 0) + 1));
  const ok = {}; keys.forEach(k => (get(k).tags?.ok || []).forEach(v => ok[v] = (ok[v] || 0) + 1));
  const sat = keys.map(k => get(k).sens).filter(x => x && x.sat && x.sat !== 'Ninguna');
  const vis = src.habits || [], hlog = src.hlog || {};
  const habPct = vis.length && reg.length ? Math.round(keys.reduce((a, k) => a + (hlog[k] || []).filter(id => vis.some(h => h.id === id)).length, 0) / (vis.length * keys.length) * 100) : null;
  const wi = keys.filter(k => psiloOf(get(k)).length && get(k).mood != null).map(k => get(k).mood), wo = keys.filter(k => !psiloOf(get(k)).length && get(k).mood != null).map(k => get(k).mood);
  const withWithout = wi.length >= 3 && wo.length >= 3 ? `${num(avg(wi))} / ${num(avg(wo))}` : '—';
  const stats = [['Días registrados', `${reg.length} de ${keys.length}`], ['Ánimo promedio', num(avg(moods))], ['Con / sin hongos', withWithout], ['Hábitos cumplidos', habPct == null ? '—' : habPct + '%']];
  const p = src.phrase, wk = p ? Object.values(p.weeks || {}).filter(Boolean).length : 0, pu = src.purpose || {}, topics = src.topics || [];
  let txt = `${src.title || 'INFORME HIFA'} · ${fmtD(from)} a ${fmtD(to)}\n\n` +
    `Días registrados: ${reg.length} de ${keys.length}\nÁnimo promedio: ${num(avg(moods))} (escala 1–5)\n` +
    (run ? `Racha de ánimo bajo: ${fmtD(keys[run.start])} a ${fmtD(keys[run.end])} (${run.len} días)\n` : 'Sin rachas de ánimo bajo de 5 días o más\n') +
    (src.noScales ? '' : `${scLine('PHQ9', 'PHQ-9')}\n${scLine('GAD7', 'GAD-7')}\n`) +
    (subLines.length ? `\nLo que tomó:\n${subLines.join('\n')}\nÁnimo con / sin hongos: ${withWithout} (observacional)\n` : '') +
    (Object.keys(eff).length ? `Efectos notados: ${Object.entries(eff).sort((a, b) => b[1] - a[1]).map(([n, c]) => `${n} (${c})`).join(', ')}\n` : '') +
    (Object.keys(st).length ? `\nEstresores: ${Object.entries(st).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([n, c]) => `${n} (${c})`).join(', ')}\n` : '') +
    (Object.keys(ok).length ? `Logros y recursos: ${Object.entries(ok).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([n, c]) => `${n} (${c})`).join(', ')}\n` : '') +
    (sat.length ? `Saturaciones sensoriales: ${sat.length}${sat.some(x => x.trig) ? ' · detonantes: ' + sat.map(x => x.trig).filter(Boolean).slice(-3).join('; ') : ''}${sat.some(x => x.help) ? ' · ayudó: ' + sat.map(x => x.help).filter(Boolean).slice(-3).join('; ') : ''}\n` : '') +
    (habPct != null ? `Hábitos cumplidos: ${habPct}%\n` : '') +
    (p ? `Frase del trimestre: ${p.verb} — "${p.text}" · practicada ${wk} ${wk === 1 ? 'semana' : 'semanas'}\n` : '') +
    (pu.compass ? `Lo que busca: ${pu.compass}\n` : '') +
    ((pu.valuesOn || []).length ? `Valores: ${pu.valuesOn.join(', ')}\n` : '') +
    (topics.length ? `\nTemas para la sesión:\n${topics.map(t => '• ' + t).join('\n')}\n` : '');
  if (includeJournal) {
    const jl = keys.filter(k => (get(k).journal || []).some(m => m.w === 'me')).map(k => `${fmtD(k)}: ${(get(k).journal || []).filter(m => m.w === 'me').map(m => m.t).join(' / ')}`);
    if (jl.length) txt += `\nBitácora:\n${jl.join('\n')}\n`;
  }
  txt += '\nResume registros personales. No es un diagnóstico.';
  return { text: txt, stats, withWithout, reg: reg.length };
}
function buildReport() {
  if (!$('#repFrom').value) { $('#repFrom').value = addDays(TODAY(), -29); $('#repTo').value = TODAY(); $('#repTopics').value = D.reportTopics || ''; }
  const from = $('#repFrom').value, to = $('#repTo').value;
  if (!from || !to || from > to) return;
  const keys = rangeKeys(daysBetween(from, to) + 1, to);
  const r = reportText({ get: dayR, scales: D.scales, phrase: D.phrase, purpose: D.purpose, habits: D.habits.filter(h => !(h.food && tca())), hlog: D.hlog,
    topics: $('#repTopics').value.split('\n').map(x => x.trim()).filter(Boolean) }, keys, $('#repJournal').checked);
  $('#repStats').innerHTML = r.stats.map(([a, b]) => `<div><dt>${a}</dt><dd>${esc(b)}</dd></div>`).join('');
  $('#repText').textContent = r.text;
}
['repFrom', 'repTo', 'repJournal'].forEach(id => $('#' + id).addEventListener('change', buildReport));
let topT; $('#repTopics').addEventListener('input', () => { clearTimeout(topT); topT = setTimeout(() => { D.reportTopics = $('#repTopics').value; save(); buildReport(); }, 400); });
$('#copyRep').onclick = () => { const t = $('#repText').textContent; (navigator.clipboard ? navigator.clipboard.writeText(t) : Promise.reject()).then(() => toast('Informe copiado')).catch(() => { const r = document.createRange(); r.selectNodeContents($('#repText')); const s = getSelection(); s.removeAllRanges(); s.addRange(r); toast('Selecciona y copia el texto'); }); };
$('#shareRep').onclick = async () => { const t = $('#repText').textContent; if (navigator.share) { try { await navigator.share({ title: 'Informe Hifa', text: t }); } catch (e) {} } else $('#copyRep').click(); };
$('#printRep').onclick = () => window.print();


/* ---------------- compartir archivos ---------------- */
async function shareOrDownload(name, body, title) {
  const mobile = /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
  if (mobile && navigator.canShare) {
    for (const type of ['application/json', 'text/plain']) {
      const file = new File([body], name, { type });
      if (navigator.canShare({ files: [file] })) {
        try { await navigator.share({ files: [file], title }); return true; }
        catch (e) { if (e.name === 'AbortError') return false; }
        break;
      }
    }
  }
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([body], { type: 'application/json' })); a.download = name;
  document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  return true;
}
const slug = t => (t || 'psicologx').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 30) || 'psicologx';
const initials = t => (t || '?').trim().split(/\s+/).filter(w => /[a-záéíóúñ]/i.test(w[0])).slice(0, 2).map(w => w[0].toUpperCase()).join('') || '?';

/* ---------------- PACIENTE: vincular y enviar ---------------- */
function renderLink() {
  const k = D.support.proKey;
  $('#linkBox').innerHTML = k
    ? `<div class="bstate"><b>Vinculadx con ${esc(k.name || 'tu psicólogx')}</b>Huella: <b style="display:inline;letter-spacing:.06em;font-variant-numeric:lining-nums tabular-nums">${esc(k.fp)}</b><br><span class="small">Pídele que te confirme que su huella es igual.</span></div><button class="btn small" type="button" data-link="change">Cambiar vínculo</button>`
    : `<label class="muted" for="proCodeIn">Pega aquí el código de tu psicólogx<textarea id="proCodeIn" class="field code" placeholder="HIFA-PRO1…"></textarea></label><button class="btn" type="button" data-link="save">Vincular</button><p class="muted small">Tu psicólogx lo encuentra en su Hifa, en «Mi código», y te lo puede enviar por WhatsApp.</p>`;
}
$('#linkBox').addEventListener('click', async e => {
  const b = e.target.closest('[data-link]'); if (!b) return;
  if (b.dataset.link === 'change') { if (!confirm('¿Quitar el vínculo actual? Podrás pegar un código nuevo.')) return; D.support.proKey = null; save(); return renderLink(); }
  try {
    const k = await parseProCode($('#proCodeIn').value);
    D.support.proKey = k; if (!D.support.psyName && k.name) D.support.psyName = k.name;
    save(); renderYo(); toast('Vinculadx. Confirma la huella en tu próxima sesión.');
  } catch (er) { toast('Ese código no es válido. Cópialo completo, desde HIFA-PRO1.'); }
});
const SCOPES = [['mood', 'Ánimo, energía, ansiedad, foco y sueño', true], ['scales', 'Escalas PHQ-9 y GAD-7', true], ['psilo', 'Hongos psilocibios', true],
  ['supp', 'Funcionales, adaptógenos, suplementos y medicación', true], ['habits', 'Hábitos y frase del trimestre', true], ['sens', 'Registro sensorial y social', true],
  ['tags', 'Estresores y logros de la bitácora', true], ['self', 'Cómo funciono, qué trabajo y mi brújula', true], ['journal', 'Textos completos de la bitácora', false]];
function renderEnviar() {
  const k = D.support.proKey;
  $('#sendNoLink').hidden = !!k; $('#sendForm').hidden = !k; if (!k) return;
  $('#sendTo').textContent = 'Para: ' + (k.name || 'tu psicólogx'); $('#sendFp').textContent = 'Huella ' + k.fp;
  $('#alias').value = D.support.alias || '';
  if (!$('#sendFrom').value) { $('#sendFrom').value = addDays(TODAY(), -29); $('#sendTo2').value = TODAY(); }
  $('#sendTo2').max = TODAY();
  const sc = D.support.scopes || Object.fromEntries(SCOPES.map(([id, , v]) => [id, v]));
  $('#scopeList').innerHTML = SCOPES.map(([id, l]) => `<label class="switch"><span>${l}${id === 'journal' ? '<small>Lo que escribiste, palabra por palabra</small>' : ''}</span><input type="checkbox" data-scope="${id}" ${sc[id] ? 'checked' : ''}></label>`).join('');
  $('#sendTopics').value = D.reportTopics || '';
}
function buildPackage(from, to, scopes, alias, topics) {
  const keys = rangeKeys(daysBetween(from, to) + 1, to), sc = new Set(scopes), days = {};
  keys.forEach(k => {
    const e = dayR(k); if (!hasData(e)) return; const o = {};
    if (sc.has('mood')) ['mood', 'en', 'an', 'fo', 'su'].forEach(f => { if (e[f] != null) o[f] = e[f]; });
    const it = (e.intake || []).filter(i => (i.cat === 'psilo' && sc.has('psilo')) || (i.cat !== 'psilo' && sc.has('supp'))).map(({ fromRoutine, ...i }) => i);
    if (it.length) o.intake = it;
    if ((sc.has('psilo') || sc.has('supp')) && (e.effects || []).length) o.effects = e.effects;
    if (sc.has('sens') && e.sens) o.sens = e.sens;
    if (sc.has('tags') && e.tags && (e.tags.st.length || e.tags.ok.length)) o.tags = e.tags;
    if (sc.has('journal') && e.journal) { const j = e.journal.filter(m => m.w === 'me').map(m => ({ w: 'me', t: m.t, at: m.at })); if (j.length) o.journal = j; }
    if (Object.keys(o).length) days[k] = o;
  });
  const pkg = { v: 1, pid: D.shareId, alias, sentAt: new Date().toISOString(), from, to, scopes, days, topics };
  if (sc.has('scales')) pkg.scales = D.scales.filter(x => x.date >= from && x.date <= to);
  if (sc.has('habits')) {
    const vis = D.habits.filter(h => !(h.food && tca()));
    pkg.habits = vis.map(({ id, n }) => ({ id, n })); pkg.hlog = {};
    keys.forEach(k => { const a = (D.hlog[k] || []).filter(id => vis.some(h => h.id === id)); if (a.length) pkg.hlog[k] = a; });
    pkg.phrase = D.phrase;
  }
  if (sc.has('self')) { pkg.minds = D.prefs.minds; pkg.goals = D.prefs.goals; pkg.purpose = { compass: D.purpose.compass, valuesOn: D.purpose.valuesOn }; }
  return pkg;
}
$('#sendPkg').onclick = async () => {
  const k = D.support.proKey; if (!k) return;
  const alias = $('#alias').value.trim(); if (!alias) { $('#alias').focus(); return toast('Escribe con qué nombre te verá'); }
  const from = $('#sendFrom').value, to = $('#sendTo2').value; if (!from || !to || from > to) return toast('Revisa las fechas');
  const scopes = $$('[data-scope]').filter(i => i.checked).map(i => i.dataset.scope); if (!scopes.length) return toast('Elige al menos una cosa para incluir');
  const topics = $('#sendTopics').value.split('\n').map(x => x.trim()).filter(Boolean);
  D.support.alias = alias; D.support.scopes = Object.fromEntries(SCOPES.map(([id]) => [id, scopes.includes(id)])); D.reportTopics = $('#sendTopics').value;
  try {
    const env = await sealFor(k.pub, buildPackage(from, to, scopes, alias, topics));
    const okk = await shareOrDownload(`hifa-para-${slug(k.name)}-${TODAY()}.json`, JSON.stringify(env), 'Paquete de Hifa');
    if (!okk) return toast('Envío cancelado');
    D.support.lastSent = new Date().toISOString(); save();
    toast('Paquete listo. Envíaselo por WhatsApp o correo.');
  } catch (e) { console.error(e); toast('No se pudo crear el paquete'); }
};

/* ---------------- PROFESIONAL ---------------- */
const proCode = () => `HIFA-PRO1.${D.pro.pub}.${b64u(new TextEncoder().encode(D.pro.name || ''))}`;
function renderCodigo() { $('#proName').value = D.pro.name || ''; $('#proFp').textContent = D.pro.fp; $('#proCode').value = proCode(); }
$('#proName').addEventListener('change', e => { D.pro.name = e.target.value.trim(); save(); renderCodigo(); });
$('#copyCode').onclick = () => { const t = proCode(); (navigator.clipboard ? navigator.clipboard.writeText(t) : Promise.reject()).then(() => toast('Código copiado')).catch(() => { $('#proCode').select(); toast('Selecciona y copia el código'); }); };
$('#shareCode').onclick = async () => {
  if (!D.pro.name) { $('#proName').focus(); return toast('Escribe primero tu nombre'); }
  const text = `Mi código de Hifa:\n${proCode()}\n\nPégalo en tu Hifa: Yo › Mi psicólogx › Vínculo. Huella: ${D.pro.fp}`;
  if (navigator.share) { try { await navigator.share({ title: 'Mi código de Hifa', text }); } catch (e) {} } else $('#copyCode').click();
};
function renderAjustes() {
  $$('#themeSeg2 button').forEach(b => b.setAttribute('aria-pressed', b.dataset.t === D.prefs.theme));
  $('#proNoanim').checked = !!D.prefs.noanim;
}
$('#themeSeg2').onclick = e => { const b = e.target.closest('button'); if (!b) return; D.prefs.theme = b.dataset.t; save(); applyPrefs(); renderAjustes(); };
$('#proNoanim').onchange = e => { D.prefs.noanim = e.target.checked; save(); applyPrefs(); };

const proGet = P => k => P.data.days[k] || {};
const proEnd = P => P.data.to || dkey(new Date(P.last));
function attention(P) {
  const d = P.data, get = proGet(P), end = proEnd(P), keys = rangeKeys(30, end), out = [];
  const phq = (d.scales || []).filter(x => x.type === 'PHQ9').sort((a, b) => a.date < b.date ? -1 : 1);
  const p9 = phq.filter(x => x.answers && x.answers[8] > 0 && daysBetween(x.date, end) <= 30).pop();
  if (p9) out.push(['c', `PHQ-9: pregunta 9 positiva (${fmtD(p9.date)})`]);
  const risk = (d.goals || []).some(g => g.startsWith('Bipolaridad') || g.startsWith('Historial de psicosis'));
  if (risk && keys.some(k => psiloOf(get(k)).length)) out.push(['c', 'Marcó bipolaridad o psicosis y registra hongos psilocibios']);
  const run = lowRun(keys, get); if (run) out.push(['c', `Ánimo bajo ${run.len} días seguidos (${fmtD(keys[run.start])}–${fmtD(keys[run.end])})`]);
  const l = phq[phq.length - 1], pv = phq[phq.length - 2];
  if (l && (l.score >= 10 || (pv && l.score - pv.score >= 5))) out.push(['a', `PHQ-9: ${l.score} (${band('PHQ9', l.score)})${pv ? `, antes ${pv.score}` : ''}`]);
  const gad = (d.scales || []).filter(x => x.type === 'GAD7').sort((a, b) => a.date < b.date ? -1 : 1).pop();
  if (gad && gad.score >= 10) out.push(['a', `GAD-7: ${gad.score} (${band('GAD7', gad.score)})`]);
  const macro = keys.filter(k => psiloOf(get(k)).some(i => i.dose === 'macro')).length; if (macro) out.push(['a', `${macro} ${macro === 1 ? 'día' : 'días'} con macrodosis`]);
  const sat = keys.filter(k => { const x = get(k).sens; return x && x.sat && x.sat !== 'Ninguna'; }).length; if (sat >= 3) out.push(['a', `${sat} saturaciones sensoriales`]);
  const since = daysBetween(dkey(new Date(P.last)), TODAY()); if (since > 14) out.push(['', `Sin paquete hace ${since} días`]);
  return out;
}
function renderPatients() {
  const ids = Object.keys(D.patients).sort((a, b) => (D.patients[b].last || '').localeCompare(D.patients[a].last || ''));
  $('#ptList').innerHTML = ids.map(id => {
    const P = D.patients[id], at = attention(P);
    return `<button type="button" class="pt ${at.some(a => a[0] === 'c') ? 'hi' : ''}" data-p="${id}"><span class="av">${esc(initials(P.alias))}</span><span style="flex:1;min-width:0;display:flex;flex-direction:column;gap:4px"><b>${esc(P.alias || 'Paciente')}</b><span class="muted small">Último paquete: ${new Date(P.last).toLocaleDateString('es-CO', { day: 'numeric', month: 'short' })} · ${P.notes.length} ${P.notes.length === 1 ? 'nota' : 'notas'}</span><span class="row" style="gap:4px">${at.slice(0, 3).map(([c, t]) => `<span class="pill ${c}">${esc(t)}</span>`).join('') || '<span class="pill g">Sin alertas</span>'}</span></span></button>`;
  }).join('') || `<div class="card"><h2>Aún no tienes pacientes</h2><p class="muted">1. En «Mi código», escribe tu nombre y comparte tu código.<br>2. Tu paciente lo pega en su Hifa y te envía un paquete por WhatsApp o correo.<br>3. Guarda el archivo y toca «Importar paquete».</p></div>`;
}
$('#ptList').onclick = e => { const b = e.target.closest('[data-p]'); if (b) { curPt = b.dataset.p; go('paciente'); } };
$('#importPkg').onclick = () => $('#pkgFile').click();
$('#pkgFile').onchange = async e => {
  const f = e.target.files[0]; e.target.value = ''; if (!f) return;
  let env; try { env = JSON.parse(await f.text()); } catch (er) { return toast('Ese archivo no es de Hifa'); }
  if (env && env.kdf) return toast('Ese archivo es una copia de seguridad, no un paquete de paciente');
  if (!env || env.app !== 'hifa' || env.type !== 'paquete-paciente') return toast('Ese archivo no es un paquete de Hifa');
  if (env.to !== D.pro.fp) return toast('Este paquete fue cifrado para otro profesional');
  let pkg; try { pkg = await openFromPatient(env); } catch (er) { return toast('No se pudo abrir el paquete'); }
  const P = (D.patients[pkg.pid] ||= { alias: pkg.alias, notes: [], received: [], data: { days: {} } });
  if (P.received.includes(pkg.sentAt)) return toast('Ese paquete ya estaba importado');
  const old = P.data, scales = [...(old.scales || [])];
  (pkg.scales || []).forEach(x => { if (!scales.some(y => y.type === x.type && y.date === x.date && y.score === x.score)) scales.push(x); });
  P.data = { ...old, ...pkg, days: { ...(old.days || {}), ...pkg.days }, scales, hlog: { ...(old.hlog || {}), ...(pkg.hlog || {}) },
    to: (old.to && old.to > pkg.to) ? old.to : pkg.to };
  P.alias = pkg.alias || P.alias; P.received.push(pkg.sentAt); P.last = pkg.sentAt;
  save(); toast(`Paquete de ${pkg.alias} importado`); curPt = pkg.pid; go('paciente');
};
let curPt = null, ptRange = 30;
const SCOPE_SHORT = { mood: 'Ánimo', scales: 'Escalas', psilo: 'Hongos', supp: 'Suplementos', habits: 'Hábitos', sens: 'Sensorial', tags: 'Estresores', self: 'Perfil', journal: 'Bitácora completa' };
$('#ptRange').onclick = e => { const b = e.target.closest('button'); if (!b) return; ptRange = +b.dataset.d; $$('#ptRange button').forEach(x => x.setAttribute('aria-pressed', x === b)); renderPatient(); };
function renderPatient() {
  const P = D.patients[curPt]; if (!P) return go('pacientes');
  const d = P.data, get = proGet(P), end = proEnd(P), keys = rangeKeys(ptRange, end);
  $('#ptHead').innerHTML = `<h1>${esc(P.alias)}</h1><div class="muted">Recibido ${new Date(P.last).toLocaleString('es-CO', { dateStyle: 'medium', timeStyle: 'short' })} · ${P.received.length} ${P.received.length === 1 ? 'paquete' : 'paquetes'}</div>` +
    `<div class="row" style="gap:4px"><span class="muted small">Comparte:</span>${(d.scopes || []).map(x => `<span class="pill g">${SCOPE_SHORT[x] || esc(x)}</span>`).join('')}</div>` +
    (((d.minds || []).length || (d.goals || []).length) ? `<div class="row" style="gap:4px">${(d.minds || []).map(x => `<span class="pill">${esc(x)}</span>`).join('')}${(d.goals || []).map(x => `<span class="pill a">${esc(x)}</span>`).join('')}</div>` : '');
  const at = attention(P);
  $('#ptAlerts').innerHTML = at.filter(a => a[0]).map(([c, t]) => `<div class="${c === 'c' ? 'alert' : 'note'}"><div><b>${esc(t)}</b></div></div>`).join('');
  const c = chartSVG(get, keys);
  $('#ptChartCard').hidden = c.count < 2;
  if (c.count >= 2) { $('#ptChart').innerHTML = c.svg; $('#ptAvg').textContent = 'promedio ' + num(c.avg); }
  const r = reportText({ title: 'RESUMEN ' + (P.alias || '').toUpperCase(), get, scales: d.scales, phrase: d.phrase, purpose: d.purpose, habits: d.habits, hlog: d.hlog, topics: d.topics, noScales: !(d.scopes || []).includes('scales') }, keys, true);
  $('#ptDays').innerHTML = `${r.reg} <small>de ${keys.length}</small>`;
  $('#ptWith').textContent = r.withWithout;
  $('#ptReport').textContent = r.text;
  $('#notes').innerHTML = [...P.notes].reverse().map(n => `<div class="notei"><div><small>${new Date(n.at).toLocaleString('es-CO', { dateStyle: 'medium', timeStyle: 'short' })}</small>${esc(n.t)}</div><button type="button" aria-label="Borrar nota" data-n="${esc(n.at)}">×</button></div>`).join('');
}
$('#addNote').onclick = () => { const t = $('#noteIn').value.trim(); if (!t) return; D.patients[curPt].notes.push({ at: new Date().toISOString(), t }); $('#noteIn').value = ''; save(); renderPatient(); toast('Nota guardada'); };
$('#notes').onclick = e => { const b = e.target.closest('[data-n]'); if (!b || !confirm('¿Borrar esta nota?')) return; const P = D.patients[curPt]; P.notes = P.notes.filter(n => n.at !== b.dataset.n); save(); renderPatient(); };
$('#copyPtRep').onclick = () => { const t = $('#ptReport').textContent; (navigator.clipboard ? navigator.clipboard.writeText(t) : Promise.reject()).then(() => toast('Resumen copiado')).catch(() => toast('Selecciona y copia el texto')); };
$('#delPatient').onclick = () => { const P = D.patients[curPt]; if (!P || !confirm(`¿Eliminar a ${P.alias} y tus notas de este dispositivo? No se puede deshacer.`)) return; delete D.patients[curPt]; save(); go('pacientes'); };

/* ---------------- actualización de la app ---------------- */
if ('serviceWorker' in navigator) navigator.serviceWorker.addEventListener('controllerchange', () => { if (KEY) toast('Hifa se actualizó. Se aplicará al volver a abrirla.'); });

boot();
