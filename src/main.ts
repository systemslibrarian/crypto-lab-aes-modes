/**
 * main.ts — Entry point for crypto-lab-aes-modes
 *
 * Initializes theme toggle, tab navigation, and mounts all mode panels.
 */

import { initTabs } from './ui';
import { mountECBPanel } from './ecb';
import { mountCBCPanel } from './cbc';
import { mountCTRPanel } from './ctr';
import { mountGCMPanel } from './gcm';
import { mountCCMPanel } from './ccm';
import { mountOraclePanel } from './oracle';

function initThemeToggle(): void {
  const button = document.getElementById('theme-toggle');
  if (!(button instanceof HTMLButtonElement)) return;

  const applyTheme = (theme: 'dark' | 'light', persist = false): void => {
    document.documentElement.setAttribute('data-theme', theme);
    if (persist) {
      localStorage.setItem('theme', theme);
    }

    button.textContent = theme === 'dark' ? '🌙' : '☀️';
    const nextLabel = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
    button.setAttribute('aria-label', nextLabel);
    button.title = nextLabel;
  };

  const initialTheme = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  applyTheme(initialTheme);

  button.addEventListener('click', () => {
    const currentTheme = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
    const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
    applyTheme(nextTheme, true);
  });
}

document.addEventListener('DOMContentLoaded', () => {
  initThemeToggle();
  initTabs();

  mountECBPanel();
  mountCBCPanel();
  mountCTRPanel();
  mountGCMPanel();
  mountCCMPanel();
  mountOraclePanel();
});
