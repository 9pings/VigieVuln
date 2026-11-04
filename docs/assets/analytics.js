(function () {
  'use strict';
  var key = 'vigievuln-audience-optout', blocked = true;
  try { blocked = localStorage.getItem(key) === '1'; } catch (e) {}
  function update() {
    var button = document.querySelector('[data-audience-optout]');
    if (!button) return;
    button.textContent = blocked ? 'Allow audience measurement' : 'Disable audience measurement';
    button.onclick = function () {
      try { blocked = !blocked; localStorage.setItem(key, blocked ? '1' : '0'); location.reload(); }
      catch (e) { button.textContent = 'Storage unavailable; measurement disabled'; }
    };
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', update); else update();
  if (blocked || navigator.doNotTrack === '1' || window.doNotTrack === '1' || navigator.globalPrivacyControl) return;
  try {
    var ref = '';
    if (document.referrer) { var r = new URL(document.referrer); if (r.protocol === 'http:' || r.protocol === 'https:') ref = r.origin; }
    var params = new URLSearchParams({ path: location.pathname, referrer: ref });
    var pixel = new Image(); pixel.referrerPolicy = 'origin';
    pixel.src = 'https://stats.vigievuln.fr/pixel.gif?' + params.toString();
  } catch (e) {}
})();
