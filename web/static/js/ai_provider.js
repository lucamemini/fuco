/* AI provider selector: fills a split-button dropdown menu from /api/ai/providers.
   Only available providers are listed; the arrow is hidden when there is nothing to choose. */
window.FucoAiProvider = (function () {
  const STORAGE_KEY = 'fuco.ai.provider';
  let current = null;

  function stored() {
    try { return localStorage.getItem(STORAGE_KEY) || null; } catch (e) { return null; }
  }

  function selected() {
    return current || stored();
  }

  function renderMenu(menu, providers, onChange, toggle) {
    menu.innerHTML = '';
    providers.forEach(function (p) {
      const li = document.createElement('li');
      const item = document.createElement('button');
      item.type = 'button';
      item.className = 'dropdown-item' + (p.id === current ? ' active' : '');
      item.textContent = p.label;
      item.addEventListener('click', function () {
        if (p.id === current) return;
        current = p.id;
        try { localStorage.setItem(STORAGE_KEY, current); } catch (e) { /* storage unavailable */ }
        toggle.title = 'Motore IA: ' + p.label;
        renderMenu(menu, providers, onChange, toggle);
        if (typeof onChange === 'function') onChange(current);
      });
      li.appendChild(item);
      menu.appendChild(li);
    });
  }

  async function init(menuId, onChange) {
    const menu = document.getElementById(menuId || 'ai-provider-menu');
    if (!menu) return;
    const toggle = menu.parentElement.querySelector('.ai-split-toggle');

    try {
      const response = await fetch('/api/ai/providers');
      if (!response.ok) throw new Error('providers unavailable');
      const data = await response.json();
      const providers = (data.providers || []).filter(function (p) { return p.available; });

      const ids = providers.map(function (p) { return p.id; });
      current = [stored(), data.default].find(function (id) { return ids.indexOf(id) !== -1; }) || ids[0] || null;

      if (toggle) {
        const label = (providers.find(function (p) { return p.id === current; }) || {}).label;
        toggle.title = label ? 'Motore IA: ' + label : 'Scegli il motore IA';
        toggle.classList.toggle('d-none', providers.length < 2);
        renderMenu(menu, providers, onChange, toggle);
      }
    } catch (e) {
      if (toggle) toggle.classList.add('d-none');
    }
  }

  return { init: init, selected: selected };
})();
