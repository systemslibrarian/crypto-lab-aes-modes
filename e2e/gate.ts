import { deflateSync } from 'node:zlib';

import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Four rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The gate this replaces
 *     pushed `*{transition:none!important;animation:none!important;
 *     scroll-behavior:auto!important}` through `addStyleTag`, then forced
 *     `open = true` on every `<details>`, un-hid all seven `role="tabpanel"`
 *     sections at once, and stripped the `hidden` attribute from every element
 *     on the page. That is a document no visitor can produce: this lab shows
 *     exactly one mode panel at a time, and `hidden` is how it carries the
 *     entire progressive-disclosure story — every math overlay, every decrypt
 *     section, every vulnerability output, every quiz explanation and every
 *     predict-answer starts hidden and is revealed by a real action. Scanning
 *     them all at once measures a page whose reading order, focus order and
 *     landmark structure are not the ones that ship.
 *
 *     Worse, suppressing motion with a style tag BYPASSES the lab's own
 *     `@media (prefers-reduced-motion: reduce)` blocks instead of exercising
 *     them — and this lab has two, one of which replaces the padding oracle's
 *     `pulse` animation with a `3px solid` outline. A style tag cannot tell you
 *     whether that substitution leaves the active byte visible. Here the
 *     preference is emulated at the browser and asserted from inside the page.
 *
 *  2. IT DROVE THE DEMOS AND SCANNED ONCE, AT THE END. `driveDemos` clicked
 *     every `[id$="-encrypt-btn"]`, every `.predict-reveal` and every
 *     `.quiz-check` it could find, waited 300ms, re-revealed everything, and
 *     ran a single axe pass. But the reveal buttons TOGGLE, the quiz buttons
 *     render a different explanation per answer, and — decisively — the
 *     encrypt buttons in six of the seven panels were not visible, so the
 *     `isVisible()` guard skipped them and their output regions were never
 *     built at all. Every failure treatment in this lab (a rejected decrypt, a
 *     tampered ciphertext, an accepted forgery, a wrong quiz answer) uses
 *     `--danger`/`--danger-bg` where the success path uses `--success`; the old
 *     gate scanned neither. Here every step is scanned in its own right.
 *
 *  3. ASSERT THE DEFAULTS, NEVER ASSUME THEM. `boot` pins down what this lab
 *     ships with — ECB selected, the other six panels hidden, no ciphertext
 *     anywhere, every predict answer and quiz explanation hidden, the demo
 *     buttons that need a ciphertext disabled, and the GCM tag length on 128.
 *     A gate that assumes the wrong half scans the wrong half.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for the page to hold still: no running animations, and no scrolling.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 *
 * Scroll position is part of "held still" here because this lab scrolls itself:
 * `activateTab` calls `tab.focus()`, which scrolls the tab strip and the page,
 * and `html { scroll-behavior: smooth }` is in force whenever the reduced-motion
 * override is not. A scroll animation does not appear in
 * `document.getAnimations()`, and measuring contrast while the document is
 * still moving reads rects that are stale by the time the ancestor walk uses
 * them.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number; __lastY?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      const still = running.length === 0 && w.__lastY === window.scrollY;
      w.__lastY = window.scrollY;
      w.__quietFrames = still ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This lab is a live example of both halves of that. Its global reduced-motion
 * block collapses durations to `0.01ms`, which is the safe form: a zero-length
 * animation still lands on its end state. But its second block does the risky
 * thing — `.oracle-byte.active { animation: none; outline: 3px solid
 * var(--warning) }` cancels `pulse` outright and substitutes a static cue. That
 * is correct only because `pulse` returns to `opacity: 1`, so cancelling it
 * lands on full opacity. This assertion checks that on every scan rather than
 * taking it on trust, and it is the reason the drive runs the padding oracle
 * with the preference genuinely in effect.
 *
 * `aria-hidden` subtrees are excluded. The cost of that exclusion is stated
 * plainly: text removed from the accessibility tree AND painted at zero opacity
 * is not checked here.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert this lab's real starting state before anything is driven.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page: an emulation that silently did nothing would
 * leave the gate certifying a different rendering than the one it claims to.
 *
 * The default assertions below are not decoration. This lab's whole teaching
 * structure is progressive disclosure through the `hidden` attribute, and the
 * gate it replaces stripped that attribute wholesale — so "which half is on
 * screen at first paint" is exactly the question that had never been asked.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // Exactly one of the seven mode panels is on screen, and it is ECB.
  await expect(page.locator('[role="tabpanel"]')).toHaveCount(7);
  await expect(page.locator('[role="tabpanel"]:not([hidden])')).toHaveCount(1);
  await expect(page.locator('#panel-ecb')).toBeVisible();
  await expect(page.locator('#tab-ecb')).toHaveAttribute('aria-selected', 'true');

  // Nothing has been encrypted, so every result region is still closed. If any
  // of these ever fails, the gate is scanning a document a visitor cannot
  // reach — which is precisely what the gate this replaces did, deliberately.
  await expect(page.locator('#ecb-key')).toBeEmpty();
  await expect(page.locator('#ecb-math')).toBeHidden();
  await expect(page.locator('#ecb-decrypt-section')).toBeHidden();
  await expect(page.locator('#ecb-image-output')).toBeHidden();
  await expect(page.locator('.predict-answer:not([hidden])')).toHaveCount(0);
  await expect(page.locator('.quiz-explain:not([hidden])')).toHaveCount(0);
  await expect(page.locator('.block-cell')).toHaveCount(0);

  // The demos that need a ciphertext refuse to run before there is one.
  await expect(page.locator('#cbc-iv-reuse-btn')).toBeDisabled();
  await expect(page.locator('#cbc-bitflip-btn')).toBeDisabled();
  await expect(page.locator('#ctr-nonce-reuse-btn')).toBeDisabled();
  await expect(page.locator('#gcm-tamper-btn')).toBeDisabled();
  await expect(page.locator('#ccm-tamper-btn')).toBeDisabled();
  await expect(page.locator('#oracle-run-btn')).toBeDisabled();

  // The one control whose default silently changes what the panel teaches.
  await expect(page.locator('#gcm-tag-length')).toHaveValue('128');

  // The glossary decorates terms at runtime; if it had not run, the tooltip
  // states below would be scanning nothing.
  await expect(page.locator('.glossary-term').first()).toBeVisible();

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender at 380px: it prints unbroken hex strings hundreds of
 * characters long, a seven-tab strip, a three-column `role="table"` of CCM
 * against GCM, and grids of fixed 40px and 36px cells whose count grows with
 * the plaintext.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That
    // cost a run elsewhere in this fleet, and this lab has the same decoy in
    // every `.hex-output` and in the `.mode-selector` tab strip.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Prefer an unclipped culprit; fall back to the widest clipped one rather
    // than reporting nothing, so the message always names something to look at.
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This is the assertion the old gate could not possibly have made, because the
 * containers at risk here only overflow once content exists. `.hex-output` is
 * `max-height: 6rem; overflow-y: auto` and holds nothing until something is
 * encrypted; the padding oracle's `role="log"` `.log-scroll` is
 * `max-height: 12rem` and empty until the attack runs. A gate that scans a
 * pristine page cannot see either.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run.
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the
 * committed workflow, and a run with it set fails at the end via
 * `reportCollected`, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything.
 *
 * Without this a collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function softly(run: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return run();
  try {
    await run();
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * Scan the page as it currently stands.
 *
 * Six assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — `expectNotBlank`, above.
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result axe
 *    simply could not finish — including `aria-prohibited-attr`, which is where
 *    an `aria-label` on a role-less `<div>` hides, a defect that never reaches
 *    the violations array at all. This lab hands `aria-label` to a lot of bare
 *    divs from JavaScript: every `.block-cell`, every `.chain-block`, every
 *    `.oracle-byte`. This assertion is what keeps that honest.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *    Load-bearing here: the block grids take their background from a palette in
 *    JavaScript, so no amount of reading the stylesheet tells you what the
 *    white block labels sit on.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. Both were being found by hand-sampling screenshot pixels, which does
 * not regress-test.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate, and this sweep has spent its whole length deleting checks
 * that could not fail. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(
        `WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`
      );
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await softly(() => expectScrollersReachable(page, label));
  await softly(() => expectNoHorizontalOverflow(page, label));
  await expectNoNewNonTextFailures(page, label);
}

/**
 * A 32x32 two-tone checkerboard, as raw PNG bytes.
 *
 * The ECB panel's image path is the headline demonstration in this lab — the
 * penguin effect — and it is the only state in which `#ecb-image-output` and
 * its two `<canvas>` elements are on screen at all. Driving it needs a real
 * file, and it needs one whose pixels REPEAT, because a photograph encrypts to
 * noise and teaches nothing: hard-edged quadrants give ECB the identical
 * 16-byte input blocks that make the leak visible.
 *
 * Built here rather than committed as a binary fixture so the bytes are
 * readable and the file cannot drift away from what the comment claims.
 */
function checkerboardPng(): Buffer {
  const W = 32;
  const H = 32;
  const raw = Buffer.alloc(H * (1 + W * 3));
  for (let y = 0; y < H; y++) {
    const off = y * (1 + W * 3);
    raw[off] = 0; // filter type 0 (None) for every scanline
    for (let x = 0; x < W; x++) {
      const dark = x < W / 2 !== y < H / 2;
      raw[off + 1 + x * 3] = dark ? 0x20 : 0xe0;
      raw[off + 2 + x * 3] = dark ? 0x20 : 0xe0;
      raw[off + 3 + x * 3] = dark ? 0x20 : 0xe0;
    }
  }
  const table = Array.from({ length: 256 }, (_, n) => {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
  });
  const crc = (b: Buffer): number => {
    let c = 0xffffffff;
    for (const x of b) c = table[(c ^ x) & 0xff]! ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const chunk = (type: string, data: Buffer): Buffer => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const body = Buffer.concat([Buffer.from(type), data]);
    const sum = Buffer.alloc(4);
    sum.writeUInt32BE(crc(body));
    return Buffer.concat([len, body, sum]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(W, 0);
  ihdr.writeUInt32BE(H, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // colour type 2 = truecolour RGB
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Four things shape the order:
 *
 *  - ONE PANEL IS ON SCREEN AT A TIME. Six of the seven `role="tabpanel"`
 *    sections carry the `hidden` attribute at any moment. The gate this
 *    replaces removed the attribute from all of them and scanned the stack;
 *    here each tab is clicked and its panel driven while it is the one that
 *    ships. That also means every `[id$="-encrypt-btn"]` outside ECB was
 *    invisible to the old gate's `isVisible()` guard, so five of the six
 *    encrypt paths were never run at all.
 *
 *  - EVERY RESULT REGION OVERWRITES THE LAST. Each panel owns one
 *    `.decrypt-output` and one `.vuln-output`, and each demo button replaces
 *    its contents. The old gate clicked several in a row and scanned once at
 *    the end, so the correct-key decrypt, the wrong-IV decrypt and the wrong-key
 *    decrypt were each destroyed before anything measured them — and they are
 *    the states that differ, using `--danger` where the happy path uses
 *    `--success`. Each is scanned in its own right here.
 *
 *  - THE FAILURE TREATMENTS ARE THE POINT OF THE LAB. A tampered ciphertext
 *    accepted by ECB, a bit-flip that rewrites `admin=0` to `admin=1`, a GCM
 *    forgery that real WebCrypto accepts, a wrong quiz answer: all of them use
 *    a palette the success path never touches. Both halves are driven.
 *
 *  - THE PADDING ORACLE ONLY EXISTS AFTER IT RUNS. Its `role="log"` scroller,
 *    its recovered-byte grid and its XOR derivation panel are empty until the
 *    attack is executed, and the log only overflows its `max-height: 12rem`
 *    after a few hundred queries. A gate that scans a pristine page cannot see
 *    any of it.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);
  const openTab = async (mode: string, label: string): Promise<void> => {
    await page.locator(`#tab-${mode}`).click();
    await expect(page.locator(`#panel-${mode}`)).toBeVisible();
    await expect(page.locator('[role="tabpanel"]:not([hidden])')).toHaveCount(1);
    await scanAt(label);
  };
  /** Reveal a panel's predict answer, scan it, and leave it open. */
  const reveal = async (mode: string): Promise<void> => {
    await page.locator(`#panel-${mode} .predict-reveal`).click();
    await expect(page.locator(`#panel-${mode} .predict-answer`)).toBeVisible();
    await scanAt(`${mode} — prediction revealed`);
  };
  /** Answer a panel's self-check and scan the explanation it renders. */
  const quiz = async (mode: string, value: string, expectClass: string): Promise<void> => {
    if (value) await page.locator(`#panel-${mode} input[value="${value}"]`).check();
    await page.locator(`#panel-${mode} .quiz-check`).click();
    await expect(page.locator(`#panel-${mode} .quiz-explain`)).toHaveClass(
      new RegExp(expectClass)
    );
    await scanAt(`${mode} — self-check ${value ? `answered "${value}"` : 'with nothing selected'}`);
  };

  await scanAt('first paint');

  await page.locator('a.skip-link').focus();
  await scanAt('skip link focused');

  // The glossary tooltip has no state of its own in the DOM — it is revealed
  // purely by `:focus-visible`/`:focus-within` on the term. Focusing a term is
  // the only way it is ever on screen for a keyboard user.
  await page.locator('#panel-ecb .glossary-term').first().focus();
  await expect(page.locator('#panel-ecb .glossary-term').first().locator('.glossary-tip')).toBeVisible();
  await scanAt('glossary tooltip open on a focused term');

  // ── ECB ─────────────────────────────────────────────────────────────────
  await reveal('ecb');

  // The default plaintext is "YELLOW SUBMARINE" twice, so the grid renders the
  // duplicate-block treatment — the one state this whole panel exists for.
  await page.locator('#ecb-encrypt-btn').click();
  await expect(page.locator('#ecb-block-grid .block-cell').first()).toBeVisible();
  await expect(page.locator('.block-cell[data-duplicate="true"]')).not.toHaveCount(0);
  await expect(page.locator('#ecb-math')).toBeVisible();
  await expect(page.locator('#ecb-decrypt-section')).toBeVisible();
  await scanAt('ecb — encrypted, duplicate blocks flagged');

  await page.locator('#ecb-decrypt-btn').click();
  await expect(page.locator('#ecb-decrypt-output .decrypt-ok')).toBeVisible();
  await scanAt('ecb — decrypted with the correct key');

  await page.locator('#ecb-decrypt-tamper-btn').click();
  await expect(page.locator('#ecb-decrypt-output')).toBeVisible();
  await scanAt('ecb — decrypted after corrupting a ciphertext block');

  // A plaintext with no repeats: every cell a different colour, no duplicate
  // marker. The palette is walked further here than the default input walks it.
  await page.locator('#ecb-plaintext').fill('The quick brown fox jumps over the lazy dog, twice over.');
  await page.locator('#ecb-encrypt-btn').click();
  await expect(page.locator('.block-cell[data-duplicate="true"]')).toHaveCount(0);
  await scanAt('ecb — encrypted with no repeated blocks');

  await quiz('ecb', '', 'quiz-incorrect');
  await quiz('ecb', 'a', 'quiz-incorrect');
  await quiz('ecb', 'b', 'quiz-correct');

  // The image path, last: once a file is attached every later click takes it.
  await page.locator('#ecb-image-upload').setInputFiles({
    name: 'checkerboard.png',
    mimeType: 'image/png',
    buffer: checkerboardPng(),
  });
  await page.locator('#ecb-encrypt-btn').click();
  await expect(page.locator('#ecb-image-output')).toBeVisible();
  await expect(page.locator('#ecb-math')).toBeHidden();
  await scanAt('ecb — image encrypted, penguin comparison on screen');

  // ── CBC ─────────────────────────────────────────────────────────────────
  await openTab('cbc', 'cbc — panel opened');
  await reveal('cbc');

  await page.locator('#cbc-encrypt-btn').click();
  await expect(page.locator('#cbc-chain-blocks .chain-block').first()).toBeVisible();
  await expect(page.locator('#cbc-math')).toBeVisible();
  await expect(page.locator('#cbc-iv-reuse-btn')).toBeEnabled();
  await scanAt('cbc — encrypted with a random IV');

  // A caller-supplied IV is a separate branch of the encrypt handler, and the
  // only way to reach the IV-reuse demo's "IDENTICAL ciphertexts" verdict.
  await page.locator('#cbc-iv').fill('000102030405060708090a0b0c0d0e0f');
  await page.locator('#cbc-encrypt-btn').click();
  await expect(page.locator('#cbc-iv-output')).toHaveText('000102030405060708090a0b0c0d0e0f');
  await scanAt('cbc — encrypted with a caller-supplied IV');

  await page.locator('#cbc-iv-reuse-btn').click();
  await expect(page.locator('#cbc-vuln-output')).toBeVisible();
  await expect(page.locator('#cbc-vuln-content')).toContainText('IDENTICAL ciphertexts');
  await scanAt('cbc — IV reuse produces identical ciphertexts');

  await page.locator('#cbc-bitflip-btn').click();
  await expect(page.locator('#cbc-vuln-content')).toContainText('Bit-flip attack');
  await scanAt('cbc — bit-flip attack');

  await page.locator('#cbc-targeted-btn').click();
  await expect(page.locator('#cbc-vuln-content')).toContainText('Targeted bit-flip puzzle');
  await scanAt('cbc — targeted bit-flip, admin=0 rewritten to admin=1');

  for (const [id, label] of [
    ['#cbc-decrypt-correct-btn', 'correct key and IV'],
    ['#cbc-decrypt-wrong-iv-btn', 'wrong IV'],
    ['#cbc-decrypt-wrong-key-btn', 'wrong key'],
    ['#cbc-decrypt-tamper-btn', 'tampered ciphertext'],
  ] as const) {
    await page.locator(id).click();
    await expect(page.locator('#cbc-decrypt-output')).toBeVisible();
    await scanAt(`cbc — decrypted with ${label}`);
  }

  await quiz('cbc', 'a', 'quiz-incorrect');
  await quiz('cbc', 'c', 'quiz-correct');

  // ── CTR ─────────────────────────────────────────────────────────────────
  await openTab('ctr', 'ctr — panel opened');
  await reveal('ctr');

  await page.locator('#ctr-plaintext').fill('ATTACK AT DAWN, bring the keystream');
  await page.locator('#ctr-plaintext2').fill('RETREAT AT DUSK, same nonce though');
  await page.locator('#ctr-encrypt-btn').click();
  await expect(page.locator('#ctr-stream-blocks .stream-row').first()).toBeVisible();
  await expect(page.locator('#ctr-math')).toBeVisible();
  await scanAt('ctr — encrypted, keystream rows shown');

  await page.locator('#ctr-nonce-reuse-btn').click();
  await expect(page.locator('#ctr-nonce-output')).toBeVisible();
  await scanAt('ctr — nonce reuse recovers the second plaintext');

  for (const [id, label] of [
    ['#ctr-decrypt-correct-btn', 'the correct nonce'],
    ['#ctr-decrypt-wrong-nonce-btn', 'a wrong nonce'],
    ['#ctr-decrypt-tamper-btn', 'a one-bit ciphertext flip'],
  ] as const) {
    await page.locator(id).click();
    await expect(page.locator('#ctr-decrypt-output')).toBeVisible();
    await scanAt(`ctr — decrypted with ${label}`);
  }

  await quiz('ctr', 'd', 'quiz-incorrect');
  await quiz('ctr', 'b', 'quiz-correct');

  // ── GCM ─────────────────────────────────────────────────────────────────
  await openTab('gcm', 'gcm — panel opened');
  await reveal('gcm');

  await page.locator('#gcm-plaintext').fill('Authenticated encryption, with associated data.');
  await page.locator('#gcm-aad').fill('session=42; route=/transfer');
  await page.locator('#gcm-encrypt-btn').click();
  await expect(page.locator('#gcm-tag')).not.toBeEmpty();
  await expect(page.locator('#gcm-math')).toBeVisible();
  await scanAt('gcm — encrypted at the recommended 128-bit tag');

  // A truncated tag is a different rendering and the reason the select exists.
  await page.locator('#gcm-tag-length').selectOption('96');
  await page.locator('#gcm-encrypt-btn').click();
  await expect(page.locator('#gcm-tag')).not.toBeEmpty();
  await scanAt('gcm — encrypted at a truncated 96-bit tag');

  await page.locator('#gcm-tamper-btn').click();
  await expect(page.locator('#gcm-tamper-output')).toBeVisible();
  await scanAt('gcm — tamper detection');

  for (const [id, label] of [
    ['#gcm-decrypt-correct-btn', 'everything correct'],
    ['#gcm-decrypt-wrong-aad-btn', 'the wrong AAD'],
    ['#gcm-decrypt-wrong-nonce-btn', 'the wrong nonce'],
    ['#gcm-decrypt-tamper-btn', 'a one-bit ciphertext flip'],
  ] as const) {
    await page.locator(id).click();
    await expect(page.locator('#gcm-decrypt-output')).toBeVisible();
    await scanAt(`gcm — decrypted with ${label}`);
  }

  // The forbidden attack: a real nonce-reuse forgery that real WebCrypto
  // accepts, and its control run that it must reject.
  await page.locator('#forbidden-run-btn').click();
  await expect(page.locator('#forbidden-output')).toBeVisible();
  await expect(page.locator('#forbidden-output [data-verdict="accepted"]')).toBeVisible();
  await scanAt('gcm — forbidden attack, forgery ACCEPTED by WebCrypto');

  await page.locator('#forbidden-control-btn').click();
  await expect(page.locator('#forbidden-output [data-verdict="rejected"]')).toBeVisible();
  await scanAt('gcm — forbidden attack control, fresh nonce, forgery rejected');

  await quiz('gcm', 'b', 'quiz-incorrect');
  await quiz('gcm', 'c', 'quiz-correct');

  // ── CCM ─────────────────────────────────────────────────────────────────
  await openTab('ccm', 'ccm — panel opened');
  await reveal('ccm');

  await page.locator('#ccm-plaintext').fill('Zigbee frame payload, authenticated by CBC-MAC.');
  await page.locator('#ccm-aad').fill('device=0x1f4; seq=9001');
  await page.locator('#ccm-encrypt-btn').click();
  await expect(page.locator('#ccm-ciphertext')).not.toBeEmpty();
  await expect(page.locator('#ccm-math')).toBeVisible();
  await scanAt('ccm — encrypted');

  await page.locator('#ccm-tamper-btn').click();
  await expect(page.locator('#ccm-tamper-output')).toBeVisible();
  await scanAt('ccm — tamper detection');

  for (const [id, label] of [
    ['#ccm-decrypt-correct-btn', 'everything correct'],
    ['#ccm-decrypt-tamper-btn', 'a one-bit ciphertext flip'],
  ] as const) {
    await page.locator(id).click();
    await expect(page.locator('#ccm-decrypt-output')).toBeVisible();
    await scanAt(`ccm — decrypted with ${label}`);
  }

  await quiz('ccm', 'c', 'quiz-incorrect');
  await quiz('ccm', 'b', 'quiz-correct');

  // ── Compare ─────────────────────────────────────────────────────────────
  await openTab('compare', 'compare — panel opened');

  await page.locator('#compare-btn').click();
  await expect(page.locator('#compare-output .compare-card')).toHaveCount(5);
  await expect(page.locator('.compare-dup-warn')).toBeVisible();
  await scanAt('compare — all five modes over a repeating plaintext');

  // Each card hides its full ciphertext behind a closed <details>; the old gate
  // forced all of them open at once from script instead of clicking a summary.
  await page.locator('#compare-output .compare-card summary').first().click();
  await expect(page.locator('#compare-output details[open]')).toHaveCount(1);
  await scanAt('compare — one ciphertext disclosure open');

  await page.locator('#compare-plaintext').fill('No repeats here at all, so nothing should be flagged as duplicated.');
  await page.locator('#compare-btn').click();
  await expect(page.locator('#compare-output .compare-card')).toHaveCount(5);
  await expect(page.locator('.compare-dup-warn')).toHaveCount(0);
  await scanAt('compare — no mode leaks structure, including ECB');

  // ── Padding oracle ──────────────────────────────────────────────────────
  await openTab('oracle', 'oracle — panel opened');
  await reveal('oracle');

  await page.locator('#oracle-plaintext').fill('Attack me!');
  await page.locator('#oracle-setup-btn').click();
  await expect(page.locator('#oracle-progress')).toBeVisible();
  await expect(page.locator('.oracle-byte')).toHaveCount(16);
  await expect(page.locator('#oracle-run-btn')).toBeEnabled();
  await scanAt('oracle — target encrypted, every byte still unknown');

  // Mid-attack, exactly one byte carries `.active`, and that class is the only
  // place in the lab where the reduced-motion block CANCELS an animation rather
  // than collapsing its duration: `.oracle-byte.active { animation: none;
  // outline: 3px solid var(--warning) }`. A cancelled animation loses its end
  // state, so the substitution is only safe because `pulse` returns to
  // `opacity: 1` — and that is a fact to check, not to assume.
  //
  // It is measured with a recording observer rather than a `scan`, because the
  // state cannot be held and cannot be sampled: the whole attack is ~2,100
  // WebCrypto calls on a single block and completes without the page ever
  // painting a frame, so BOTH an assertion that starts polling after `click()`
  // resolves AND a `requestAnimationFrame` poll armed beforehand find the run
  // already over — measured, both of them, before this was written this way.
  // A MutationObserver cannot miss it: it is delivered as a microtask
  // immediately after the class is assigned, while the element still carries
  // it. Nothing is changed by installing it — it only reads.
  await page.evaluate(() => {
    const w = window as unknown as { __activeByte?: unknown };
    const grid = document.getElementById('oracle-byte-grid')!;
    const snap = (): void => {
      if (w.__activeByte) return;
      const el = document.querySelector('.oracle-byte.active');
      if (!el) return;
      const cs = getComputedStyle(el);
      let effective = 1;
      let n: Element | null = el;
      while (n) {
        effective *= parseFloat(getComputedStyle(n).opacity);
        n = n.parentElement;
      }
      w.__activeByte = {
        animationName: cs.animationName,
        effectiveOpacity: effective,
        outline: `${cs.outlineStyle} ${cs.outlineWidth}`,
        color: cs.color,
        background: cs.backgroundColor,
        text: (el.textContent ?? '').trim(),
      };
    };
    new MutationObserver(snap).observe(grid, {
      attributes: true,
      subtree: true,
      childList: true,
    });
  });
  await page.locator('#oracle-run-btn').click();

  // The log only overflows its 12rem cap after a few hundred queries, so the
  // keyboard-reachability assertion has nothing to bite on until now.
  await expect(page.locator('#oracle-recovered-text')).not.toBeEmpty({ timeout: 300_000 });
  await expect(page.locator('.oracle-byte.recovered')).toHaveCount(16);
  await expect(page.locator('#oracle-math')).toBeVisible();

  const active = await page.evaluate(
    () => (window as unknown as { __activeByte?: Record<string, unknown> }).__activeByte
  );
  expect(active, 'no byte was ever marked active during the attack').toBeTruthy();
  expect(active, 'the active byte under reduced motion').toMatchObject({
    animationName: 'none',
    effectiveOpacity: 1,
    outline: 'solid 3px',
  });
  expect(active!.text, 'the active byte must still be painting its placeholder').not.toBe('');

  await scanAt('oracle — plaintext fully recovered, query log populated');

  await quiz('oracle', 'b', 'quiz-incorrect');
  await quiz('oracle', 'c', 'quiz-correct');

  // ── Keyboard tab navigation ─────────────────────────────────────────────
  // `initTabs` binds Arrow/Home/End on the tablist and moves focus as well as
  // selection, so this is a genuinely different state from a click.
  await page.locator('#tab-oracle').press('Home');
  await expect(page.locator('#tab-ecb')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#tab-ecb')).toBeFocused();
  await scanAt('tablist — Home returns to the first tab');

  await page.locator('#tab-ecb').press('ArrowRight');
  await expect(page.locator('#tab-cbc')).toHaveAttribute('aria-selected', 'true');
  await scanAt('tablist — ArrowRight advances to the next tab');

  reportCollected();
}
