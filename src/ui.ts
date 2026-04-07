/**
 * ui.ts — Panel controller and shared utilities
 *
 * Handles tab navigation, theme toggle, and shared helper functions
 * used across all mode modules.
 */

// ─── Hex encoding/decoding ───

export function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexDecode(hex: string): Uint8Array {
  const clean = hex.replace(/\s/g, '');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// ─── Text encoding ───

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function textToBytes(text: string): Uint8Array {
  return encoder.encode(text);
}

export function bytesToText(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

// ─── BufferSource helper (TS 5.7+ compat) ───
// WebCrypto accepts Uint8Array at runtime. These wrappers
// avoid Uint8Array<ArrayBufferLike> vs BufferSource type errors
// in algorithm param fields (iv, counter, additionalData).

/* eslint-disable @typescript-eslint/no-explicit-any */
export function aesEncrypt(
  algorithm: any,
  key: CryptoKey,
  data: Uint8Array
): Promise<ArrayBuffer> {
  return crypto.subtle.encrypt(algorithm, key, data);
}

export function aesDecrypt(
  algorithm: any,
  key: CryptoKey,
  data: Uint8Array
): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt(algorithm, key, data);
}
/* eslint-enable @typescript-eslint/no-explicit-any */

// ─── PKCS#7 padding ───

export function pkcs7Pad(data: Uint8Array, blockSize: number): Uint8Array {
  const padLen = blockSize - (data.length % blockSize);
  const padded = new Uint8Array(data.length + padLen);
  padded.set(data);
  for (let i = data.length; i < padded.length; i++) {
    padded[i] = padLen;
  }
  return padded;
}

// ─── Error announcement ───

export function announceError(msg: string): void {
  const region = document.getElementById('error-region');
  if (region) {
    region.textContent = msg;
    // Clear after 5 seconds
    setTimeout(() => {
      if (region.textContent === msg) region.textContent = '';
    }, 5000);
  }
  console.error(msg);
}

// ─── Theme toggle ───

export function initThemeToggle(): void {
  const btn = document.getElementById('theme-toggle') as HTMLButtonElement;
  if (!btn) return;

  // Check saved preference or system preference
  const saved = localStorage.getItem('crypto-lab-theme');
  if (saved) {
    document.documentElement.setAttribute('data-theme', saved);
  } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
    document.documentElement.setAttribute('data-theme', 'dark');
  }

  btn.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('crypto-lab-theme', next);
  });
}

// ─── Tab controller ───

export function initTabs(): void {
  const tabs = document.querySelectorAll<HTMLButtonElement>('[role="tab"]');
  const panels = document.querySelectorAll<HTMLElement>('[role="tabpanel"]');

  function activateTab(tab: HTMLButtonElement): void {
    // Deactivate all
    tabs.forEach(t => {
      t.setAttribute('aria-selected', 'false');
      t.tabIndex = -1;
    });
    panels.forEach(p => {
      p.hidden = true;
    });

    // Activate selected
    tab.setAttribute('aria-selected', 'true');
    tab.tabIndex = 0;
    const panelId = tab.getAttribute('aria-controls');
    if (panelId) {
      const panel = document.getElementById(panelId);
      if (panel) panel.hidden = false;
    }

    tab.focus();
  }

  tabs.forEach(tab => {
    tab.addEventListener('click', () => activateTab(tab));

    tab.addEventListener('keydown', (e: KeyboardEvent) => {
      const tabArr = Array.from(tabs);
      const idx = tabArr.indexOf(tab);
      let nextIdx = idx;

      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
        e.preventDefault();
        nextIdx = (idx + 1) % tabArr.length;
      } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
        e.preventDefault();
        nextIdx = (idx - 1 + tabArr.length) % tabArr.length;
      } else if (e.key === 'Home') {
        e.preventDefault();
        nextIdx = 0;
      } else if (e.key === 'End') {
        e.preventDefault();
        nextIdx = tabArr.length - 1;
      }

      if (nextIdx !== idx) {
        activateTab(tabArr[nextIdx]);
      }
    });
  });

  // Initialize: first tab active
  if (tabs.length > 0) {
    activateTab(tabs[0]);
  }
}
