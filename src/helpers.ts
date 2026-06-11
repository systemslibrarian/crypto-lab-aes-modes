/**
 * helpers.ts — Shared teaching helpers
 *
 * - Glossary tooltips (IV, nonce, AAD, AEAD, tag, GHASH, …)
 * - Predict-before-reveal prompts
 * - Block-level math renderer (P ⊕ prev → AES → C, with real hex)
 * - Self-check quiz handler
 * - XOR utility for math display
 */

import { hexEncode } from './ui';

// ─── Glossary terms ──────────────────────────────────────────────

const GLOSSARY: Record<string, string> = {
  IV: 'Initialization Vector — a per-message public value that randomizes encryption so the same plaintext never produces the same ciphertext. Must be unpredictable for CBC.',
  Nonce: 'Number used once — a per-message value that must never repeat with the same key. Reuse is catastrophic for CTR/GCM/CCM.',
  AAD: 'Additional Authenticated Data — header/metadata authenticated by the tag but not encrypted. Used to bind ciphertext to a context (e.g. session id).',
  AEAD: 'Authenticated Encryption with Associated Data — modes that provide confidentiality AND integrity in one step (GCM, CCM, ChaCha20-Poly1305).',
  Tag: 'Authentication tag — short MAC appended to ciphertext. Decryption rejects the message if the tag fails to verify.',
  GHASH: 'Galois-field hash function used by GCM to compute the authentication tag over ciphertext and AAD.',
  'CBC-MAC':
    'A MAC built by CBC-encrypting the message with a zero IV and using the final block as the tag. CCM authentication primitive.',
  'PKCS#7':
    'A padding scheme: pad to the next block boundary by appending N bytes each holding value N. Padding-validity leaks are the basis of the padding oracle attack.',
  Counter:
    'In CTR mode, a 16-byte block formed from the nonce + an incrementing counter. AES encrypts each counter to produce keystream blocks.',
  Keystream:
    'The pseudorandom byte stream produced by AES on successive counter blocks. CTR encryption is simply plaintext XOR keystream.',
};

export function mountGlossary(): void {
  // Find every span with [data-term] and attach tooltip on hover/focus.
  const terms = document.querySelectorAll<HTMLElement>('[data-term]');
  terms.forEach((el) => {
    const term = el.getAttribute('data-term') ?? '';
    const def = GLOSSARY[term];
    if (!def) return;

    el.classList.add('glossary-term');
    el.setAttribute('tabindex', '0');
    el.setAttribute('role', 'button');
    el.setAttribute('aria-label', `${term}: ${def}`);

    const tip = document.createElement('span');
    tip.className = 'glossary-tip';
    tip.setAttribute('role', 'tooltip');
    tip.innerHTML = `<strong>${term}</strong> — ${def}`;
    el.appendChild(tip);
  });
}

// ─── Predict-before-reveal prompts ──────────────────────────────

export function mountPredictPrompts(): void {
  const prompts = document.querySelectorAll<HTMLElement>('.predict-prompt');
  prompts.forEach((p) => {
    const btn = p.querySelector<HTMLButtonElement>('.predict-reveal');
    const reveal = p.querySelector<HTMLElement>('.predict-answer');
    if (!btn || !reveal) return;
    reveal.hidden = true;
    btn.addEventListener('click', () => {
      reveal.hidden = !reveal.hidden;
      btn.textContent = reveal.hidden ? 'Reveal' : 'Hide';
      btn.setAttribute('aria-expanded', reveal.hidden ? 'false' : 'true');
    });
  });
}

// ─── XOR utility ────────────────────────────────────────────────

export function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const len = Math.min(a.length, b.length);
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = a[i] ^ b[i];
  return out;
}

// ─── Block math renderer ────────────────────────────────────────
//
// Each call replaces the container with a sequence of math rows.
// Rows are short — they pull the first 8 hex chars so the math fits.

function short(bytes: Uint8Array): string {
  const h = hexEncode(bytes);
  return h.length > 16 ? h.slice(0, 16) + '…' : h;
}

export interface MathStep {
  label: string;
  expression: string; // already-formatted hex math, may include unicode ops
  note?: string;
}

export function renderMath(container: HTMLElement, steps: MathStep[]): void {
  container.innerHTML = '';
  steps.forEach((s) => {
    const row = document.createElement('div');
    row.className = 'math-row';
    row.innerHTML = `
      <span class="math-label">${s.label}</span>
      <code class="math-expr">${s.expression}</code>
      ${s.note ? `<span class="math-note">${s.note}</span>` : ''}
    `;
    container.appendChild(row);
  });
}

// Helpers for each mode to build their math steps.

export function ecbMath(
  plaintextPadded: Uint8Array,
  ciphertext: Uint8Array,
  blockSize = 16,
  maxBlocks = 3
): MathStep[] {
  const steps: MathStep[] = [];
  const n = Math.min(ciphertext.length / blockSize, maxBlocks);
  for (let i = 0; i < n; i++) {
    const p = plaintextPadded.slice(i * blockSize, (i + 1) * blockSize);
    const c = ciphertext.slice(i * blockSize, (i + 1) * blockSize);
    steps.push({
      label: `Block ${i}`,
      expression: `AES_K(${short(p)}) = ${short(c)}`,
      note: 'each block independent — same input → same output',
    });
  }
  if (ciphertext.length / blockSize > maxBlocks) {
    steps.push({ label: '…', expression: `(${ciphertext.length / blockSize - maxBlocks} more blocks)`, note: '' });
  }
  return steps;
}

export function cbcMath(
  plaintextPadded: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  blockSize = 16,
  maxBlocks = 3
): MathStep[] {
  const steps: MathStep[] = [];
  const n = Math.min(ciphertext.length / blockSize, maxBlocks);
  let prev = iv;
  for (let i = 0; i < n; i++) {
    const p = plaintextPadded.slice(i * blockSize, (i + 1) * blockSize);
    const c = ciphertext.slice(i * blockSize, (i + 1) * blockSize);
    const prevLabel = i === 0 ? 'IV' : `C${i - 1}`;
    steps.push({
      label: `Block ${i}`,
      expression: `AES_K(P${i} ⊕ ${prevLabel}) = AES_K(${short(p)} ⊕ ${short(prev)}) = ${short(c)}`,
      note: i === 0 ? 'IV randomizes the first block' : 'each block depends on all previous blocks',
    });
    prev = c;
  }
  if (ciphertext.length / blockSize > maxBlocks) {
    steps.push({ label: '…', expression: `(${ciphertext.length / blockSize - maxBlocks} more blocks)`, note: '' });
  }
  return steps;
}

export function ctrMath(
  nonce: Uint8Array,
  plaintext: Uint8Array,
  ciphertext: Uint8Array,
  blockSize = 16,
  maxBlocks = 3
): MathStep[] {
  const steps: MathStep[] = [];
  const numBlocks = Math.ceil(plaintext.length / blockSize);
  const n = Math.min(numBlocks, maxBlocks);
  const nonceHex = hexEncode(nonce).slice(0, 16) + '…';
  for (let i = 0; i < n; i++) {
    const p = plaintext.slice(i * blockSize, (i + 1) * blockSize);
    const c = ciphertext.slice(i * blockSize, (i + 1) * blockSize);
    steps.push({
      label: `Block ${i}`,
      expression: `keystream = AES_K(${nonceHex}||${(i + 1).toString().padStart(8, '0')}); C${i} = P${i} ⊕ keystream = ${short(p)} ⊕ ks = ${short(c)}`,
      note: i === 0 ? 'counter starts at 1 (block 0 reserved for tag in GCM/CCM)' : 'each block uses next counter value',
    });
  }
  if (numBlocks > maxBlocks) {
    steps.push({ label: '…', expression: `(${numBlocks - maxBlocks} more blocks)`, note: '' });
  }
  return steps;
}

export function gcmMath(
  nonce: Uint8Array,
  plaintext: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array
): MathStep[] {
  const blockSize = 16;
  const nonceHex = hexEncode(nonce).slice(0, 16) + '…';
  const steps: MathStep[] = [
    {
      label: 'Step 1',
      expression: `H = AES_K(0…0)`,
      note: 'GHASH subkey from encrypting a zero block',
    },
    {
      label: 'Step 2',
      expression: `J₀ = ${nonceHex} || 00 00 00 01`,
      note: 'initial counter block (96-bit nonce path)',
    },
  ];
  const n = Math.min(Math.ceil(plaintext.length / blockSize), 2);
  for (let i = 0; i < n; i++) {
    const p = plaintext.slice(i * blockSize, (i + 1) * blockSize);
    const c = ciphertext.slice(i * blockSize, (i + 1) * blockSize);
    steps.push({
      label: `Block ${i}`,
      expression: `C${i} = P${i} ⊕ AES_K(J₀+${i + 1}) = ${short(p)} ⊕ ks = ${short(c)}`,
      note: '',
    });
  }
  steps.push({
    label: 'Tag',
    expression: `T = AES_K(J₀) ⊕ GHASH_H(AAD, C, lengths) = ${short(tag)}`,
    note: 'binds ciphertext + AAD + lengths in one tag',
  });
  return steps;
}

export function ccmMath(
  nonce: Uint8Array,
  plaintext: Uint8Array,
  ciphertext: Uint8Array,
  tagLen = 16
): MathStep[] {
  const blockSize = 16;
  const nonceHex = hexEncode(nonce).slice(0, 16) + '…';
  const steps: MathStep[] = [
    {
      label: 'Pass 1',
      expression: `T = CBC-MAC_K(B₀ || AAD || P) (first ${tagLen} bytes)`,
      note: 'authenticate first',
    },
    {
      label: 'Pass 2',
      expression: `S₀ = AES_K(${nonceHex}||00); encTag = T ⊕ S₀`,
      note: 'encrypt the tag with counter 0',
    },
  ];
  const n = Math.min(Math.ceil(plaintext.length / blockSize), 2);
  for (let i = 0; i < n; i++) {
    const p = plaintext.slice(i * blockSize, (i + 1) * blockSize);
    const c = ciphertext.slice(i * blockSize, (i + 1) * blockSize);
    steps.push({
      label: `Block ${i}`,
      expression: `C${i} = P${i} ⊕ AES_K(${nonceHex}||${(i + 1).toString().padStart(2, '0')}) = ${short(p)} ⊕ ks = ${short(c)}`,
      note: '',
    });
  }
  return steps;
}

// ─── Self-check quiz handler ────────────────────────────────────

export function mountQuizzes(): void {
  const quizzes = document.querySelectorAll<HTMLElement>('.quiz-card');
  quizzes.forEach((q) => {
    const correct = q.getAttribute('data-correct') ?? '';
    const explain = q.querySelector<HTMLElement>('.quiz-explain');
    const checkBtn = q.querySelector<HTMLButtonElement>('.quiz-check');
    const opts = q.querySelectorAll<HTMLInputElement>('input[type="radio"]');
    if (!checkBtn || !explain) return;
    explain.hidden = true;

    checkBtn.addEventListener('click', () => {
      let selected: string | null = null;
      opts.forEach((o) => {
        if (o.checked) selected = o.value;
      });
      if (selected === null) {
        explain.hidden = false;
        explain.innerHTML = '<em>Pick an answer first.</em>';
        explain.className = 'quiz-explain quiz-incorrect';
        return;
      }
      const ok = selected === correct;
      explain.hidden = false;
      explain.className = `quiz-explain ${ok ? 'quiz-correct' : 'quiz-incorrect'}`;
      const why = q.getAttribute(ok ? 'data-why-correct' : 'data-why-wrong') ?? '';
      explain.innerHTML = `<strong>${ok ? '✓ Correct.' : '✗ Not quite.'}</strong> ${why}`;
    });
  });
}
