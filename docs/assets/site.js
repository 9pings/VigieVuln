'use strict';

// The page remains readable with JavaScript disabled. These controls enhance it.
const themeButton = document.querySelector('.theme-toggle');
function syncThemeLabel() {
  themeButton.setAttribute('aria-label', `Switch to ${document.documentElement.dataset.theme === 'light' ? 'dark' : 'light'} theme`);
}
syncThemeLabel();
themeButton.addEventListener('click', () => {
  const theme = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  document.documentElement.dataset.theme = theme;
  try { localStorage.setItem('vigievuln-theme', theme); } catch { /* Storage may be disabled. */ }
  syncThemeLabel();
});

const navigation = document.getElementById('main-nav');
const menuButton = document.querySelector('.menu-toggle');
function closeMenu() {
  navigation.classList.remove('is-open');
  menuButton.setAttribute('aria-expanded', 'false');
  menuButton.setAttribute('aria-label', 'Open navigation');
}
menuButton.addEventListener('click', () => {
  const open = navigation.classList.toggle('is-open');
  menuButton.setAttribute('aria-expanded', String(open));
  menuButton.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
});
navigation.addEventListener('click', event => { if (event.target.closest('a')) closeMenu(); });
document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && menuButton.getAttribute('aria-expanded') === 'true') {
    closeMenu();
    menuButton.focus();
  }
});
document.addEventListener('click', event => { if (!event.target.closest('.site-nav')) closeMenu(); });
matchMedia('(min-width: 1051px)').addEventListener('change', event => { if (event.matches) closeMenu(); });

let statusTimer;
const status = document.querySelector('.copy-status');
document.querySelectorAll('[data-copy]').forEach(button => {
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(button.dataset.copy);
      status.textContent = 'Command copied to clipboard.';
    } catch {
      status.textContent = 'Clipboard unavailable. Select and copy the command manually.';
    }
    clearTimeout(statusTimer);
    statusTimer = setTimeout(() => { status.textContent = ''; }, 3500);
  });
});

// Accessible benchmark tabs: selection, focus, panel labels, and arrow-key navigation.
document.querySelectorAll('.tabs').forEach((bar, group) => {
  bar.setAttribute('aria-label', 'Benchmark ecosystem');
  const tabs = [...bar.querySelectorAll('.tab')];
  const panels = [...bar.parentElement.querySelectorAll('.panel')];
  function select(tab, focus = false) {
    for (const item of tabs) {
      const active = item === tab;
      item.setAttribute('aria-selected', String(active));
      item.tabIndex = active ? 0 : -1;
    }
    for (const panel of panels) panel.hidden = panel.dataset.eco !== tab.dataset.eco;
    if (focus) tab.focus();
  }
  tabs.forEach((tab, index) => {
    tab.id = `eco-tab-${group}-${tab.dataset.eco}`;
    const panel = panels.find(item => item.dataset.eco === tab.dataset.eco);
    if (panel) {
      panel.id = `eco-panel-${group}-${tab.dataset.eco}`;
      panel.setAttribute('role', 'tabpanel');
      panel.setAttribute('aria-labelledby', tab.id);
      tab.setAttribute('aria-controls', panel.id);
    }
    tab.addEventListener('click', () => select(tab));
    tab.addEventListener('keydown', event => {
      let next;
      if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
      if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
      if (event.key === 'Home') next = 0;
      if (event.key === 'End') next = tabs.length - 1;
      if (next !== undefined) { event.preventDefault(); select(tabs[next], true); }
    });
  });
  select(tabs.find(tab => tab.getAttribute('aria-selected') === 'true') || tabs[0]);
});

const sectionLinks = [...navigation.querySelectorAll('a[href^="#"]')];
const sections = sectionLinks.map(link => document.querySelector(link.getAttribute('href'))).filter(Boolean);
let ticking = false;
function updateSection() {
  const current = sections.filter(section => section.getBoundingClientRect().top <= 150).at(-1) || sections[0];
  for (const link of sectionLinks) {
    if (link.hash === `#${current.id}`) link.setAttribute('aria-current', 'location');
    else link.removeAttribute('aria-current');
  }
  ticking = false;
}
window.addEventListener('scroll', () => {
  if (!ticking) { ticking = true; requestAnimationFrame(updateSection); }
}, { passive: true });
updateSection();
