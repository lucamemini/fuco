/* AI provider selector: fills a <select> from /api/ai/providers and remembers the choice. */
window.FucoAiProvider = (function () {
  const STORAGE_KEY = 'fuco.ai.provider';

  function stored() {
    try { return localStorage.getItem(STORAGE_KEY) || null; } catch (e) { return null; }
  }

  function selected(selectId) {
    const el = document.getElementById(selectId || 'ai-provider-select');
    if (el && el.value) return el.value;
    return stored();
  }

  async function init(selectId, onChange) {
    const el = document.getElementById(selectId || 'ai-provider-select');
    if (!el) return;

    try {
      const response = await fetch('/api/ai/providers');
      if (!response.ok) throw new Error('providers unavailable');
      const data = await response.json();

      el.innerHTML = '';
      (data.providers || []).forEach(function (p) {
        const opt = document.createElement('option');
        opt.value = p.id;
        opt.textContent = p.label + (p.available ? '' : ' (non disponibile)');
        opt.disabled = !p.available;
        el.appendChild(opt);
      });

      const wanted = [stored(), data.default].find(function (id) {
        return (data.providers || []).some(function (p) { return p.id === id && p.available; });
      });
      if (wanted) el.value = wanted;
    } catch (e) {
      el.disabled = true;
      return;
    }

    el.addEventListener('change', function () {
      try { localStorage.setItem(STORAGE_KEY, el.value); } catch (e) { /* storage unavailable */ }
      if (typeof onChange === 'function') onChange(el.value);
    });
  }

  return { init: init, selected: selected };
})();
