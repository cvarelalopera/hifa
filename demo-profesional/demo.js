/* Hifa · modo demo: carga los datos de ejemplo y los guarda aparte de tu Hifa real. */
(function () {
  var CFG = {"db": "hifa-demo-profesional", "key": "demo profesional hifa", "label": "Demo profesional · Ps. Laura Martínez · 3 pacientes"};
  var css = '.demo-bar{position:sticky;top:0;z-index:50;display:flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:space-between;' +
    'background:#6E5A86;color:#fff;padding:8px 14px;font:500 13px/1.35 Lexend,system-ui,sans-serif}' +
    '.demo-bar b{font-weight:700;letter-spacing:.04em}.demo-bar code{font-family:inherit;background:rgba(255,255,255,.18);padding:1px 6px;border-radius:6px}' +
    '.demo-bar button{border:1px solid rgba(255,255,255,.6);background:transparent;color:#fff;border-radius:999px;padding:4px 12px;font:inherit;cursor:pointer}';
  var st = document.createElement('style'); st.textContent = css; document.head.appendChild(st);

  function bar() {
    var d = document.createElement('div'); d.className = 'demo-bar'; d.setAttribute('role', 'note');
    d.innerHTML = '<span><b>DEMO</b> · ' + CFG.label + ' · datos ficticios · clave <code>' + CFG.key + '</code></span>';
    var r = document.createElement('button'); r.type = 'button'; r.textContent = 'Reiniciar demo';
    r.onclick = function () {
      if (!confirm('¿Volver a los datos de ejemplo? Se borra lo que hayas cambiado en esta demo.')) return;
      try { if (typeof DB !== 'undefined' && DB.db) DB.db.close(); } catch (e) {}
      var q = indexedDB.deleteDatabase(CFG.db);
      q.onsuccess = q.onerror = q.onblocked = function () { location.reload(); };
    };
    d.appendChild(r); document.body.insertBefore(d, document.body.firstChild);
  }

  var vis = function (s) { var e = document.querySelector(s); return e && !e.hidden; };
  var tries = 0;
  function auto() {
    if (vis('#app')) return;
    if (vis('#fNew')) {
      fetch('demo.json', { cache: 'no-store' }).then(function (r) { return r.text(); }).then(function (txt) {
        document.getElementById('toRestore').click();
        var dt = new DataTransfer(); dt.items.add(new File([txt], 'demo.json', { type: 'application/json' }));
        document.getElementById('rf').files = dt.files;
        document.getElementById('rp').value = CFG.key;
        document.getElementById('fRestore').requestSubmit();
      });
      return;
    }
    if (vis('#fUnlock')) { document.getElementById('up').value = CFG.key; document.getElementById('fUnlock').requestSubmit(); return; }
    if (tries++ < 100) setTimeout(auto, 100);
  }
  document.addEventListener('DOMContentLoaded', function () { bar(); setTimeout(auto, 150); });
  /* si Hifa se bloquea por inactividad, vuelve a abrir la demo sola */
  document.addEventListener('visibilitychange', function () { if (!document.hidden) { tries = 0; setTimeout(auto, 300); } });
})();
