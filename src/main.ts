/**
 * main.ts — Entry point for crypto-lab-aes-modes
 *
 * Initializes theme toggle, tab navigation, and mounts all mode panels.
 */

import { initThemeToggle, initTabs } from './ui';
import { mountECBPanel } from './ecb';
import { mountCBCPanel } from './cbc';
import { mountCTRPanel } from './ctr';
import { mountGCMPanel } from './gcm';
import { mountCCMPanel } from './ccm';
import { mountOraclePanel } from './oracle';

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
