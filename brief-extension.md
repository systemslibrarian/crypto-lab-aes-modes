# Extension brief — `crypto-lab-aes-modes`

**2026-10-20. Extension to a live lab; no new repository.** Written against
`crypto-lab-aes-modes` at `e21f33489cc4` and `audits/_MASTER-TEMPLATE.md` (catalog
`f48d9d2f2f06`). Template §5: "Extend, never restructure." Source of the gap: Katz–Lindell,
*Introduction to Modern Cryptography*, 3rd ed. (CRC Press, 2021), §3.6.3. It presents ECB, CBC,
chained CBC, **OFB** and CTR, and says OFB "can be shown to be CPA-secure if F is a
pseudorandom function", that the keystream "can be done independently of the actual message",
and that, unlike CBC, "it is not required that F be invertible".

**Verdict: extension — one new tab, "OFB", between CTR and GCM, plus an OFB card in the
Compare tab.**

## What the lab has now

Read at `e21f33489cc4`:

- **Seven tabs:** ECB, CBC, CTR, GCM, CCM, Compare, Oracle (`index.html:200–224`). Panels start
  at `index.html:231`. They are mounted in `src/main.ts:42–57`, and `initTabs` (`src/ui.ts:89`)
  handles arrow, Home and End keys.
- **The single-block AES trick the lab already uses:** `ecbEncryptBlock` (`src/ecb.ts:35`,
  module-private) runs one AES block encryption through WebCrypto AES-CBC with a zero IV and
  keeps the first 16 bytes. Decryption uses `@noble/ciphers` `ecb` (`ecb.ts:53–55`). OFB only
  ever needs the forward direction, so it can be built entirely on the first.
- **Known answers:** `src/ecb.test.ts:31` pins the FIPS 197 (2001) Appendix C.1 vector and
  `:38` the four SP 800-38A F.1.1 ECB-AES128 blocks. **Both run through `@noble/ciphers`' `ecb`,
  not through the lab's WebCrypto encrypt path.** At this commit no published vector reaches
  `ecbEncryptBlock` directly. OFB would sit on that path, so this extension pins it.
- **The CTR nonce-reuse exhibit** (`src/ctr.ts:159`) — the two-time-pad recovery this extension
  reuses in shape, with its overlap-length honesty (`ctr.ts:172–173`, `recoveredBytes`).
  `ctrMath` / `renderMath` (`src/helpers.ts:195`, `:129`) is the step-row pattern to copy.
- **Compare tab:** `mountComparePanel` (`src/compare.ts:94`) builds one card per mode with
  `appendCard`.
- **Tests:** vitest in a Node environment (`vitest.config.ts`). The e2e suite is `a11y.spec.ts`,
  `functional.spec.ts`, `glossary.spec.ts`, `hidden-attribute.spec.ts` and `gate.ts`. **There
  is no `e2e/claims.spec.ts` at this commit.** `e2e/gate.ts:169` asserts **7** `role="tabpanel"`.
  `src/forbidden.ts:277`/`:287` already render `data-verdict` markers.
- **Non-text contrast baseline:** `e2e/nontext-baseline.ts:20–28` lists every `.mode-tab` button's
  control boundary at 1.0:1 against a 3:1 requirement. Its header says the file "IS A TO-DO
  LIST… a finding NOT listed here fails the run… the file can only shrink". **A new
  `#tab-ofb.mode-tab` will be a new finding and will fail the gate.** See ARCHITECTURE.
- **README:** no `## Exhibits` section at this commit. "What It Is" (`README.md:3`) lists the
  modes, and "Correctness & Tests" (`README.md:38`) lists the known answers.
- `src/main.ts:16` still carries `initThemeToggle`, a legacy toggle that `index.html:73`
  suppresses with CSS. **Leave both alone**; the catalog's `theme-sync` tracks them.

**Overlap check.** Before building, grep the sibling clones for `\bOFB\b|output feedback` and
report what you find. When this brief was written that grep matched nothing.

## What to add — the OFB tab

**Plain-language intro:** OFB turns AES into a stream of random-looking bytes by encrypting
the IV, then encrypting that output, then encrypting *that*, and so on. The message is XORed
with the stream. The stream doesn't depend on the message at all, so it can be prepared before
you know what you'll send. The cost is that it can only be computed in order.

**The headline mechanism, shown:** the keystream chain `y₀ = IV`, `yᵢ = AES_K(yᵢ₋₁)`, drawn as
boxes feeding each other, with `cᵢ = yᵢ ⊕ mᵢ` below each box. Show it beside a miniature of
CTR's independent counter boxes, so the one structural difference — feedback versus counter —
is visible.

**Five short acts, each computed live:**

1. **Precompute, then encrypt.** "Generate keystream" runs before any plaintext is typed. An
   instrumented counter of AES evaluations shows `n` calls during generation and **0** during
   the XOR. This is the "preprocessing" advantage in K-L's words.
2. **Random access costs.** "Decrypt only block i" counts AES evaluations: **i** for OFB and
   **1** for CTR. K-L: CTR can "recover the ith block of the plaintext from the ciphertext using
   only a single evaluation of F". Both counts come from the instrumented block function, not
   from a formula.
3. **IV reuse is a two-time pad.** Encrypt two messages under one IV. Show `C₁ ⊕ C₂ = P₁ ⊕ P₂`,
   and recover `P₂` from a known `P₁` over the overlapping length only, keeping the honesty rule
   from `ctr.ts`. Link OTP Vault's crib-dragging.
4. **Bit-flip malleability.** Flip bit *j* of the ciphertext and exactly bit *j* of the
   plaintext flips. There is no error and no spreading into neighbouring blocks, unlike CBC
   (link the CBC tab).
5. **No padding.** A 60-byte message gives a 60-byte ciphertext, because the final keystream
   block is truncated. Show the lab's CBC padding next to it for contrast.

Also add **an OFB card in the Compare tab** (`compare.ts`), with status "confidentiality only".

## SECURITY / CORRECTNESS INVARIANTS

1. Encryption and decryption are the same function, and **neither ever calls an AES decryption**.
   A unit test spies on `crypto.subtle.decrypt` and asserts zero calls. This is K-L's "F need not
   be invertible", made checkable.
2. The keystream depends only on (key, IV). A test changes the plaintext and asserts the
   keystream bytes are identical.
3. The final keystream block is truncated, never padded. Ciphertext length equals plaintext
   length exactly.
4. A fresh random 16-byte IV is the default for every encryption. Reusing an IV is possible only
   through the act-3 control, which is visibly marked "deliberately broken".
5. The AES evaluation counter wraps the one block function every OFB call goes through, so the
   numbers in acts 1–2 can't come from anywhere else.
6. Key sizes are 128 or 256 bits. Chromium's WebCrypto doesn't support 192-bit AES, so don't
   offer it.

## ARCHITECTURE

- **Export the block function.** Export `ecbEncryptBlock` from `src/ecb.ts`, or move it to a new
  `src/aesBlock.ts` and import it into `ecb.ts`, whichever keeps `ecb.ts`'s diff smallest. Wrap
  it in a counting decorator for the OFB tab.
- `src/ofb.ts` — `ofbKeystream(key, iv, blocks, counter?)`, `ofbXor(key, iv, data)` (encrypt and
  decrypt), `ofbDecryptBlock(key, iv, ct, i)` for act 2, and `mountOFBPanel()`. Follow the
  `mountCTRPanel` shape.
- `src/helpers.ts` — add `ofbMath(...)` beside `ctrMath`.
- `src/ofb.test.ts`.
- `index.html` — tab button `#tab-ofb` after `#tab-ctr`, and its `role="tabpanel"`
  `#panel-ofb`.
- `src/main.ts` — `mountOFBPanel()` after `mountCTRPanel()`. Touch nothing else in that file.
- **Non-text contrast.** The new tab inherits `.mode-tab` and will reproduce the 1.0:1 boundary
  the baseline records for its seven siblings. The file is built to shrink, so the right fix
  is to give `.mode-tab` a ≥ 3:1 boundary (kickoff.md: use the `--control-border` token) and
  **delete the seven existing entries**, which the baseline's own rules then require. If that is
  more than you want to take on in this extension, **stop and ask Paul**. Adding an eighth entry
  contradicts the file's header.
- `// [extension] point` in `ofb.ts` for CFB (see EXTENSION SEAMS).

## UI

- Key size (128/256), an IV field (hex, prefilled random) with a "new random IV" button, and a
  plaintext textarea.
- Act 1: "Generate keystream" then "Encrypt", with the evaluation counter beside each.
- Act 2: a block-index input with "Decrypt only this block", reporting the OFB count beside
  the CTR count.
- Act 3: a second plaintext and "Encrypt both with the same IV".
- Act 4: a clickable ciphertext bit strip, plus a preset "PAY 0100 → PAY 9100" edit that
  computes the XOR mask from the two plaintexts.
- Act 5: a length readout.
- A predict prompt in the lab's existing `.predict-prompt` pattern: "Flip one ciphertext bit.
  How many plaintext bits change?"
- All output regions are `aria-live="polite"`. Stacks below 640px.

## VISUAL SEMANTICS

- **Act 3 recovery** → ALARM ("⚠ keystream reused — P₂ recovered"). Recovering plaintext is the
  mode failing.
- **Act 4 decryption of a modified ciphertext** → ALARM, reading `DECRYPTED — AND MODIFIED`.
  Never a green "decrypted" chip. OFB raises no error by construction, and the page says so
  rather than inventing one.
- **Acts 1, 2 and 5** are factual readouts in neutral styling.
- The OFB status chip reads "CONFIDENTIALITY ONLY", in the same chip family as the other tabs.
- Icon plus text plus colour every time; check in grayscale.

## EDGE CASES

- IV not exactly 32 hex characters → refuse, naming the length found. Never pad or truncate an
  IV.
- Empty plaintext → empty ciphertext, with a note. This isn't an error.
- Block index out of range in act 2 → refuse with the valid range.
- Act 3 with `P₁` shorter than `P₂` → report recovered bytes as min(|P₁|, |P₂|) of |P₂|, as
  `ctr.ts` does.
- Act 4 with non-UTF-8 output after a flip → show hex, and render invalid bytes as `·`
  (OTP Vault's convention). Don't throw.
- A key-size change after keystream generation → retire the keystream and say why.

## EXTENSION SEAMS

1. **CFB** — SP 800-38A §6.3 with the F.3 vectors. `@noble/ciphers` 2.4.0 exports `cfb`, which
   can serve as a test reference. Not built.
2. **Stateful OFB** — K-L notes the variant that continues from `y_ℓ` without sending a new IV
   is secure, and is a synchronized stream-cipher mode. A two-message demo, not built.
3. A **reduced-width OFB** (feedback of fewer bits than the block) to show cycle length. If
   added, cite a primary source for the cycle-length claim; none was verified for this brief.

## Tests

**Unit (`src/ofb.test.ts`, vitest, Node WebCrypto):**

- **OFB known answers, through the lab's own WebCrypto path.** The NIST CSRC "Examples with
  Intermediate Values" `AES_OFB.pdf` values, all four blocks (64 bytes, so well over one
  block), IV `000102030405060708090a0b0c0d0e0f`:
  - OFB-AES128, key `2b7e1516…4f3c`: ciphertext `3b3fd92e…fb4a`, `7789508d…d825`,
    `9740051e…edcc`, `304c6528…ae5e`.
  - OFB-AES256, key `603deb10…dff4`: ciphertext `dc7e84bf…3860`, `4febdc67…b08d`,
    `71ab47a0…c408`, `0126141d…e484`.
  - Plaintext is the standard four-block `6bc1bee2…3710`.
  - Pin each published output block (keystream) as well as the ciphertext.
  - Citation: the same values are SP 800-38A's Appendix F.4.1 / F.4.5. This brief's author
    could read the SP 800-38A PDF only through F.3.2. Confirm F.4 matches before citing the
    section number, and cite the CSRC page regardless.
- **Partial final block:** encrypting the first 60 bytes yields exactly the first 60 bytes of
  the published ciphertext. This is a derived known answer; say so in the comment.
- **The block function itself:** SP 800-38A F.1.1 and F.1.5 ECB block #1 (`3ad77bb4…ef97`,
  `f3eed1bd…81f8`) **through the exported WebCrypto block function**. This closes the gap where
  `ecb.test.ts` pins only noble's `ecb`.
- **Independent route:** an OFB built inside the test from `@noble/ciphers` `ecb`
  (`disablePadding`), chained by hand, must equal `ofbXor` for random keys, IVs and lengths
  0–200 bytes.
- Invariant 1 (spy: no `crypto.subtle.decrypt` call) and invariant 2 (keystream independent of
  the plaintext).
- Act 2's counts: OFB uses exactly *i* evaluations, CTR exactly 1.

**Claims — create `e2e/claims.spec.ts`** per §4.1b. None exists at this commit, so start it with
this tab's claims and flag the rest of the lab to Paul as a separate job.

- **Re-derivation by a different WebCrypto route.** The page prints key, IV, the keystream
  blocks and the ciphertext. In `page.evaluate`, recompute `yᵢ₊₁ = AES_K(yᵢ)` with **AES-CTR**
  (counter block = `yᵢ`, encrypting 16 zero bytes), not the source's AES-CBC trick. Assert
  every printed block.
- **Parts sum to whole:** printed ciphertext ⊕ printed plaintext = printed keystream, truncated
  to length.
- **Counter cross-check:** the act-2 counts equal the number of keystream rows the page draws.
- **Retirement:** changing the key size retires the keystream and the page says so.
  Re-selecting the same size does not.

**§4.1c mutations.** This tab renders verdicts, so record concrete patches in a script, following
the shape of `crypto-lab-mac-race/scripts/check-crc-mutations.mjs` (`bc4f683362e4`). At least:

1. Feedback uses `cᵢ` instead of `yᵢ` (the mode silently becomes CFB) → known answers fail.
2. The final block is padded instead of truncated → the length claim fails.
3. Act 3 draws a fresh IV for the second message → the recovery claim fails.
4. Act 4's verdict is styled calm → the verdict-class claim fails.
5. The counter is incremented during the XOR → the act-1 "0 during encrypt" claim fails.

**§4.1d negative claim:** *"OFB gives confidentiality only: a modified ciphertext decrypts
without any error, to a plaintext the attacker changed bit for bit."*

- **Fixture:** act 4's preset. Decryption completes, the length matches, the output is valid
  text, and every check the tab renders passes. The verdict reads `DECRYPTED — AND MODIFIED`,
  with the sentence visible in that state.
- Assert all three §4.1d points. Delete the sentence and assertion 3 fails.

**Gate (§4.1a):** `e2e/gate.ts:169` goes from 7 to 8 tabpanels. Add the new panel to whatever
the gate's hidden-panel checks enumerate, with structure only. Re-run the Home/ArrowRight
keyboard scan at `gate.ts:877–884` unchanged; it starts from `#tab-ecb`, so it is unaffected.

## README and card follow-up

- **What It Is:** add `OFB` to the list of modes, as a confidentiality-only stream mode.
- **Correctness & Tests:** add the OFB known answers with their source, the block-function pin,
  and the new claims file.
- The README has no `## Exhibits` section. Template §5 lists one. Don't add it as part of this
  extension; mention the gap in your handoff.
- **Catalog handoff (do not edit `../crypto-lab`):** proposed chip `AES-OFB` (implemented). The
  existing chips stay.

## Do not touch

The legacy theme toggle (`src/main.ts:16`, suppressed at `index.html:73`), the CCM known
answers, the padding oracle, the forbidden-attack exhibit and its `data-verdict` markers, and
the header.

## Sources

- Katz, Lindell. *Introduction to Modern Cryptography*, 3rd ed., CRC Press, 2021 (ISBN
  9780815354369) — §3.6.3 (OFB, CTR, Figure 3.8). Checked against the book's text.
- M. Dworkin. NIST SP 800-38A, *Recommendation for Block Cipher Modes of Operation: Methods and
  Techniques*, December 2001 — §6.4 (OFB), Appendix F.1.1/F.1.5 (read), F.4 (see the caveat in
  Tests).
- NIST CSRC, "Examples with Intermediate Values", `AES_OFB.pdf` — the OFB values quoted above.
- Chromium WebCrypto status page (chromium.org/blink/webcrypto): "192 bit AES keys are not
  supported".
