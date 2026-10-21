# Extension brief — `crypto-lab-aes-modes` (CFB)

**2026-10-21. Extension to a live lab; no new repository.** Written against
`crypto-lab-aes-modes` at `882ed58d4221` (after the OFB extension landed) and
`audits/_MASTER-TEMPLATE.md` (catalog `88f75e7edc6f`). Template §5: "Extend, never
restructure."

**This is a separate extension from the OFB one.** The draft gap check
(`draft/understanding-cryptography-2e`) asked that the commissioned OFB task not be expanded.
OFB has since shipped, and its `brief-extension.md` named CFB as extension seam 1. This brief is
that seam, as its own job.

- Save this file at the repo root as `brief-extension-cfb.md`.
- Write your handoff to `extension-handoff-cfb.md`.
- Don't touch the OFB files `brief-extension.md` and `extension-handoff.md`.

Source of the gap: Paar & Pelzl, *Understanding Cryptography* (1st ed., 2010), §5.1.4 (CFB),
checked against the book's text. It is also the draft gap check's residual rank 7.

**Verdict: extension — one new tab, "CFB", between OFB and GCM, plus a CFB card in
Compare.**

## What the lab has now

Read at `882ed58d4221`:

- **Eight tabs** (`index.html:200–228`): ECB, CBC, CTR, OFB, GCM, CCM, Compare, Oracle.
  - `#tab-ofb` is at `:212`, with its chip at `:213`; `#panel-ofb` is at `:584`.
  - `e2e/gate.ts:169` asserts **8** `role="tabpanel"`.
- **The OFB tab is the template:**
  - `src/ofb.ts` exports `EvaluationCounter` (`:6`) and a module-private counted `block()` over
    `ecbEncryptBlock` (`src/ecb.ts:36`, exported).
  - **The main IV field has a used-IV guard.** A `usedIVs` set (`src/ofb.ts:54`) and
    `if (usedIVs.has(...)) iv = freshIV()` (`:83`) replace any reused IV.
  - `src/ofbBroken.ts` isolates the deliberate IV reuse. `ofbMath` is at
    `src/helpers.ts:225`. The OFB Compare card is at `src/compare.ts:152` (`appendCard` at
    `:70`).
- **Mutation script:** `scripts/check-ofb-mutations.mjs` writes `mutation-evidence.json`
  (`:44`) and refuses to run unless the OFB sources are committed and clean. Its six cases
  anchor on exact strings in `src/ofb.ts` and `src/ofbBroken.ts`. One of them,
  `'ciphertext feedback'`, turns OFB into CFB.
- **Claims:** `e2e/claims.spec.ts`, created by the OFB extension. The OFB stream is re-derived
  via WebCrypto AES-CTR.
  - The verdict assertion pattern to copy is at `:72`:
    `toHaveAttribute('data-verdict','modified')` plus `toHaveClass('ofb-alarm')`.
  - There is a 320px a11y test at `:99`.
- **Gate scans:** the OFB scan walk is at `e2e/gate.ts:701–715` (`openTab`, `reveal`, then
  `scanAt` per state).
- **Non-text baseline:** the OFB extension fixed the `.mode-tab` boundaries and removed every
  `mode-tab` entry, so 0 remain. Confirm `#tab-cfb` produces no new finding.
- **`@noble/ciphers` 2.4.0** exports `cfb` (CFB-128 only; checked in the package's `aes.js`).
  Use it as a **test reference** only.

**Overlap check:** grep the sibling clones for `\bCFB\b|cipher feedback`. At brief time the
matches were all in this repo:

- the seam comment `src/ofb.ts:24`;
- `mutation-evidence.json`;
- `brief-extension.md:117/159/210`;
- `extension-handoff.md:58`;
- in the catalog, `tools/catalog-vocab.js:61`, the `AES-CFB` term.

None implements CFB. Report what you find.

## What to add — the CFB tab

**Plain-language intro.** "CFB also turns AES into a stream. Instead of feeding AES its own
output (OFB), it feeds AES the **ciphertext you just produced**. That one change has three
consequences. Encryption can't start before you know the message. A damaged or missing piece of
ciphertext heals after a short stretch. And whoever knows part of the plaintext can rewrite
it."

**The headline mechanism, shown:** the chain I₁ = IV, Oᵢ = AES_K(Iᵢ), Cᵢ = Pᵢ ⊕ Oᵢ,
Iᵢ₊₁ = Cᵢ, drawn as boxes. Put a miniature of OFB's chain beside it, and highlight **the one
arrow that differs**: in CFB the ciphertext goes back into AES, in OFB the AES output does.

**Segment size.** One selector, **s = 128 (default) or s = 8**, used by **acts 1 and 3 only**.
**Acts 2, 4 and 5 are fixed to CFB-128**, and each says so in its heading. At s = 8:

- a bit flip damages the rest of its byte's 16-byte window, not "one bit plus one block";
- the gadget of act 5 cannot write a chosen block.

Running those acts at s = 8 would make the page's claims false.

**Five short acts, each computed live:**

1. **Ciphertext feeds back** (s = 128 or 8).
   - Encrypt and decrypt.
   - The instrumented counter shows that encryption cannot be precomputed: AES input i+1 is Cᵢ,
     which needs Pᵢ. Contrast OFB act 1.
   - Decryption can run every AES call up front, because each input is a ciphertext segment
     already received.
   - Neither direction ever calls AES decryption.
2. **One flipped bit** (CFB-128).
   - Flip bit j of Cᵢ and see:
     - exactly bit j of Pᵢ flips;
     - **Pᵢ₊₁ is garbled**;
     - Pᵢ₊₂ onward is correct.
   - Add a comparison strip computed from the lab's own modes:
     - OFB flips one bit and spreads nothing;
     - CBC garbles Pᵢ and flips bit j of Pᵢ₊₁.

     **CFB and CBC are mirror images.** Link the CBC tab.
3. **Lose a byte, heal anyway** (s = 128 or 8).
   - CFB-8 (SP 800-38A's s = 8): delete one ciphertext byte. Only bytes within the next **16**
     received positions can decrypt wrong; after that, everything is correct again.
   - CFB-128 behaves differently:
     - deleting one byte means it never recovers;
     - deleting one **aligned** 16-byte block garbles one block, then it recovers;
     - an unaligned 16-byte deletion damages two blocks.
   - OFB and CTR are shown for contrast: a deletion desynchronises them for good.
   - **Then Zerologon: CFB-8 with a fixed zero IV.**
     - With IV = 0¹²⁸ and an all-zero plaintext, CFB-8 outputs all-zero ciphertext **exactly
       when the first byte of AES_K(0¹²⁸) is 00**. The page proves this from the chain on
       screen: the register never leaves zero.
     - It then searches random keys live, **capped at 4,096 keys**, with Cancel and a "no hit
       within the cap" state. The expected number of tries is 256, and the chance of no hit in
       4,096 is about e⁻¹⁶.
     - Cite Tervoort (Secura, September 2020). Netlogon's ComputeNetlogonCredential "defines
       that this IV is fixed and should always consist of 16 zero bytes", and "for 1 in 256
       keys, applying AES-CFB8 encryption to an all-zero plaintext will result in all-zero
       ciphertext".
     - The page shows that mode property and nothing more; Netlogon is not implemented.
4. **IV reuse leaks less than OFB, but not nothing** (CFB-128).
   - Encrypt two messages under one IV. C₁ ⊕ C₂ = P₁ ⊕ P₂ holds for **every block up to and
     including the first block where the plaintexts differ**, and not after. OFB's act 3 leaks
     the whole overlap.
   - Draw the leaked prefix, and recover blocks from a known P₁ over that prefix only, keeping
     `ctr.ts`'s overlap-honesty rule.
5. **Rewrite a known block — the EFAIL gadget** (CFB-128, the §4.1d fixture).
   - Let Pᵢ be known (default: the 16-byte header `PAY ALICE   0100`). Set
     Cᵢ′ = Cᵢ ⊕ Pᵢ ⊕ X for a chosen 16-byte X.
   - Decryption completes with no error. Pᵢ becomes exactly X, Pᵢ₊₁ is garbled, and every other
     block is unchanged.
   - Cite EFAIL (USENIX Security 2018) §3.2: in CFB, "the block after the chosen plaintext block
     becomes a random block". §5.3.1 builds the same gadget inside OpenPGP's CFB variant. The
     lab runs it on SP 800-38A CFB-128, and the page says so.

Also add **a CFB card in Compare** (`compare.ts`): status "CONFIDENTIALITY ONLY", note
"ciphertext feeds back; self-synchronising".

## SECURITY / CORRECTNESS INVARIANTS

1. **No AES decryption, ever.** A unit test spies on `crypto.subtle.decrypt` and asserts zero
   calls, as OFB's does.
2. **The feedback is the ciphertext.** One test changes Pᵢ and asserts that AES input i+1
   changes, which is the property OFB lacks.
3. **Segments are s = 128 and s = 8 only.** CFB-1 is out of scope, and the tab says so. The
   final partial segment is truncated, never padded, and length out equals length in.
4. **IV policy.**
   - The main IV field defaults to a fresh random 16-byte IV and **uses OFB's used-IV guard**:
     a reused IV is replaced, as at `src/ofb.ts:83`.
   - An all-zero IV typed into the main field is **refused** with a pointer to act 3.
   - IV reuse (act 4) and the zero IV (act 3, Zerologon) are reachable only through their own
     controls, each marked "deliberately broken".
   - `src/cfbBroken.ts` is the only module whose functions bypass the used-IV guard.
5. **One counted block function.** The act-1 counts and the act-3 key-search count go through a
   single counting wrapper over `ecbEncryptBlock`, as OFB's do.
6. **Key sizes are 128/256 only**, because Chromium WebCrypto has no AES-192. This matches OFB.
7. **The Zerologon search reports keys tried**, never "time to break Netlogon".

## ARCHITECTURE

- `src/cfb.ts`:
  - `cfbEncrypt(key, iv, data, s, counter?)`;
  - `cfbDecrypt(key, iv, data, s, counter?)`;
  - `cfbDecryptInputs(...)` for act 1;
  - `mountCFBPanel()`.
  - It imports the `EvaluationCounter` type from `ofb.ts` and `ecbEncryptBlock` from `ecb.ts`.
- `src/cfbBroken.ts`:
  - `reuseCFB` (act 4);
  - `zeroIvSearch(cap, onProgress)` (act 3), which uses a **zero IV it constructs itself**;
  - `gadget(ct, i, known, chosen)` (act 5).
- `src/helpers.ts`: add `cfbMath(...)` beside `ofbMath`.
- `src/cfb.test.ts`.
- `index.html`: `#tab-cfb` after `#tab-ofb`, and `#panel-cfb` after `#panel-ofb`.
- `src/main.ts`: `mountCFBPanel()` after `mountOFBPanel()`. Touch nothing else there.
- **Leave `src/ofb.ts` and `src/ofbBroken.ts` byte-identical**, including the `// [extension]
  point` comment at `ofb.ts:24`. Editing either would force a re-run of the OFB mutation script,
  which rewrites the OFB evidence file.
- `scripts/check-cfb-mutations.mjs`, writing `mutation-evidence-cfb.json`, in the OFB script's
  shape.
- Verdict elements carry `data-verdict` plus a class, following the OFB pattern.

## UI

- Key size (128/256); an IV in hex, prefilled random, with "new IV"; a plaintext textarea; the
  segment selector for acts 1 and 3.
- Act 2: a clickable ciphertext bit strip, plus the three-mode comparison strip.
- Act 3: "Delete byte n" with a byte index, and "Delete aligned block". Then the Zerologon panel
  with "Search keys", a running "keys tried / 4,096" counter, and Cancel.
- Act 4: a second plaintext and "Encrypt both with the same IV", with the leaked prefix
  highlighted block by block.
- Act 5: the known-block field, a chosen-block field (exactly 16 bytes, counted live), and
  "Rewrite".
- Predict prompts on act 2 ("how many plaintext blocks change?") and act 3 ("after one lost
  byte, how many bytes go wrong?").
- `aria-live="polite"` on every output region. Stacks below 640px; works at 320px.

## VISUAL SEMANTICS

- **Act 5's result is ALARM.**
  - `data-verdict="modified"` with an alarm class, reading **`DECRYPTED — AND MODIFIED`**.
  - Pᵢ = X is highlighted, and Pᵢ₊₁ is marked "garbled".
  - Never show a green "decrypted" chip. CFB raises no error by construction, and the page says
    so rather than inventing one.
- **Act 4's recovery is ALARM** ("⚠ IV reused — blocks 1–k recovered").
- **A Zerologon hit in act 3 is ALARM**: "⚠ all-zero plaintext encrypted to all-zero ciphertext
  under this key".
- Act 3's resynchronisation readout is neutral: the mode working as designed.
- Icon plus text plus colour every time. Check in grayscale.

## EDGE CASES

- IV not 32 hex characters → refuse, naming the length found. All-zero IV in the main field →
  refuse (invariant 4).
- Empty plaintext → empty ciphertext, with a note.
- Act 2 flip in the **last** block → only that block's bit changes, because there is no next
  block to garble. Say so.
- Act 3 delete index ≥ length → refuse, giving the valid range. A CFB-8 deletion within the
  last 16 bytes → fewer wrong bytes are possible; report the actual count.
- Act 3 Zerologon with no hit within the cap → report "no hit in 4,096 keys" honestly. That is
  improbable but not an error.
- Act 4 with plaintexts identical throughout → the whole overlap leaks. That is the formula's
  edge; report it.
- Act 5 known block that doesn't match the real Pᵢ (the user edited it) → the result is
  X ⊕ (typed ⊕ real), not X. Say so.
- Changing the key, segment size or IV retires dependent results and says why. Re-selecting the
  same value is a no-op.

## EXTENSION SEAMS

1. **CFB-1** (s = 1), with the CSRC CFB1 vectors. Not built.
2. **The relocated EFAIL gadget.** Copy a (Cᵢ₋₁, Cᵢ) pair elsewhere to write X anywhere (EFAIL
   §5.3.1). Not built.
3. **OpenPGP's resync CFB variant.** A primary source is required. Not built.

## Tests

**CFB known answers (unit, Vitest), through the lab's own WebCrypto path.** These are the NIST
CSRC "Examples with Intermediate Values" `AES_CFB.pdf` values, checked by the brief author and
again by an independent reviewer. IV `000102030405060708090a0b0c0d0e0f`; plaintext is the
standard `6bc1bee2…3710`.

- **CFB128-AES128**, key `2b7e1516…4f3c`. Ciphertext:
  - `3b3fd92eb72dad20333449f8e83cfb4a`
  - `c8a64537a0b3a93fcde3cdad9f1ce58b`
  - `26751f67a3cbb140b1808cf187a4f4df`
  - `c04b05357c5d1c0eeac4c66f9ff7f2e6`
- **The AES output blocks Oᵢ for that vector.** These are derived as **Cᵢ ⊕ Pᵢ of the CSRC
  vector**, and the CSRC file prints no intermediate rows:
  - `50fe67cc996d32b6da0937e99bafec60`
  - `668bcf60beb005a35354a201dab36bda`
  - `16bd032100975551547b4de89daea630`
  - `36d42170a312871947ef8714799bc5f6`

  Label them as derived.
- **CFB128-AES256**, key `603deb10…dff4`:
  - `dc7e84bfda79164b7ecd8486985d3860`
  - `39ffed143b28b1c832113c6331e5407b`
  - `df10132415e54b92a13ed0a8267ae2f9`
  - `75a385741ab9cef82031623d55b1e471`
- **CFB8-AES128**, over the first 16 plaintext bytes (16 segments): `3b79424c9c0dd436bace9e0ed4586a4f`.
- **CFB8-AES256**: `dc1f1a8520a64db55fcc8ac554844e88`.
- **Citation.** Cite the CSRC page. SP 800-38A Appendix F.3 carries the same examples, but the
  brief author did not read it. Confirm section numbers before citing any. SP 800-38A's CFB8
  example runs 18 bytes; the CSRC file shows 16. Pin what you have verified.

**Independent routes (unit):**

- `cfbEncrypt(s = 128)` against `@noble/ciphers` `cfb`, for random keys, IVs and lengths 0–200;
- CFB-8 against a test-local byte-shift chain built on `@noble/ciphers` `ecb`
  (`disablePadding`);
- decrypt∘encrypt = identity at both segment sizes.

**Properties (unit).** These are the acceptance checks, derived from the mode's definition, not
from the code. The brief author and the reviewer both confirmed each one against
pycryptodome.

- **CFB-128 bit flip** in bit j of Cᵢ: Pᵢ differs in exactly bit j, Pᵢ₊₁ differs, and Pᵢ₊₂… are
  equal.
- **CFB-8, deleting one byte at k:** the set of wrong received bytes is a subset of
  [k, k+15], and every later byte is correct. Assert subset, because some of the 16 can match
  by chance.
- **CFB-128 deletion:** deleting one byte means no resynchronisation. Deleting one aligned
  block means exactly the next block is wrong.
- **IV reuse:** C₁ ⊕ C₂ = P₁ ⊕ P₂ on blocks 0…d, where d is the first differing block, and the
  equality fails on block d+1 for random later blocks.
- **Zero IV, through `zeroIvSearch`'s own IV construction:**
  - for 2,000 seeded keys, all-zero CFB-8 ciphertext of an 8-byte zero plaintext occurs **iff**
    AES_K(0)[0] = 0;
  - **at least one hit occurs** in that set, so the iff isn't vacuous (the reviewer saw 4 hits
    for seeds 0–1999).
- **Gadget:** Pᵢ′ = X exactly, Pᵢ₊₁′ ≠ Pᵢ₊₁, and every other block is unchanged.

**Claims (`e2e/claims.spec.ts`, §4.1b):**

- **Re-derivation by a different WebCrypto route.** The page prints key, IV, AES inputs, AES
  outputs and ciphertext. In `page.evaluate`, recompute Oⱼ = AES_K(Iⱼ) with **AES-CTR** (counter
  block = Iⱼ, encrypting 16 zero bytes), as the OFB claims do. Assert every printed Oⱼ, and
  assert that the next input matches the printed ciphertext segment.
- **Parts sum to whole, per segment size:**
  - at s = 128, printed C ⊕ printed P = printed O, truncated to length;
  - at s = 8, each ciphertext byte ⊕ plaintext byte = the first byte of that segment's Oⱼ.
- **Act 2 strip:** the test recomputes CBC and OFB over the same input with the same flip, and
  asserts which bytes the page marks as changed for each mode.
- **Act 3, per segment size:**
  - at s = 8, every highlighted wrong byte lies in [k, k+15], and their count equals the
    printed count;
  - at s = 128, the highlighted damage matches the test's own recomputation.
- **Act 4:** the highlighted leak prefix length equals the test's own first-differing-block
  index + 1.
- **Act 3 Zerologon hit:** in `page.evaluate`, recompute AES_K(0)[0] for the printed key and
  assert 00.
- **Verdicts:** act 5 asserts `data-verdict="modified"` **and** the alarm class. Acts 3 and 4
  assert their alarm classes too.
- **Also:** a 320px a11y test for the new states, in the shape of `claims.spec.ts:99`, plus
  retirement and the no-op guard on key, IV and segment changes.

**§4.1c mutations.** Break the mode, never a flag. Record each as a concrete patch (file,
unique anchor, replacement) in `scripts/check-cfb-mutations.mjs`. Each kill meets the four
§4.1c rules.

1. The feedback is Oᵢ instead of Cᵢ, so CFB silently becomes OFB → the known answers fail.
2. Decryption feeds back the **plaintext** instead of the ciphertext → the round trip and the
   known answers fail.
3. The CFB-8 register shifts by 16 bits instead of 8 → the CFB8 vectors fail.
4. The final segment is padded → the length claim fails.
5. The act-2 strip's CBC comparison is computed with the error on the wrong block → the act-2
   strip claim fails, because it recomputes CBC in the test.
6. `zeroIvSearch` builds a random IV instead of 0¹²⁸ → the zero-IV iff unit test fails, as does
   the hit claim.
7. `gadget` XORs its delta into Cᵢ₋₁ instead of Cᵢ (a CBC-shaped gadget). That alters Pᵢ₋₁ and
   garbles Pᵢ → the gadget property fails.
8. The act-5 verdict element gets the neutral class and `data-verdict` → the verdict assertion
   fails.
9. Delete the negative-claim sentence → §4.1d assertion 3 fails.

**§4.1d negative claim:** *"CFB-128 gives confidentiality only: anyone who knows one plaintext
block can replace it with any block of their choosing, at the cost of one garbled block, and
decryption reports no error."*

- **Fixture:** act 5's default. Every check the tab renders passes:
  - decryption completes;
  - the length matches;
  - **block i equals X**;
  - **every block other than i and i+1 equals the original**.
- The verdict reads `DECRYPTED — AND MODIFIED`, with the sentence visible in that state.
- Assert all three §4.1d points:
  - delete the sentence and assertion 3 fails;
  - break the length check inside the fixture and assertion 2 fails.

**Gate (§4.1a):**

- `e2e/gate.ts:169` goes from 8 to 9 tabpanels.
- Add the CFB panel to the hidden-panel checks, with structure only.
- **Add a CFB scan walk after the OFB one (`gate.ts:715`)**, with one `scanAt` for each of:
  - encrypted;
  - flipped bit;
  - deleted byte at s = 8;
  - Zerologon hit;
  - reused IV;
  - rewritten block.

**Fail-closed paths, each a NAMED test:**

- bad IV length;
- all-zero IV in the main field;
- empty plaintext;
- a flip in the last block;
- a delete index out of range;
- Zerologon with no hit within the cap;
- a wrong known block;
- a chosen block that is not 16 bytes;
- a key or segment change retiring results;
- zero `subtle.decrypt` calls.

## README and card follow-up

- **What It Is:** add `CFB` (CFB-128 and CFB-8) as a confidentiality-only, self-synchronising
  stream mode.
- **Correctness & Tests:** the CFB known answers with their source, the noble route, and the
  property tests.
- **Real-World Usage:** two lines.
  - OpenPGP's CFB, broken in practice by EFAIL's gadgets where clients did not enforce
    integrity.
  - Netlogon's zero-IV AES-CFB8 (Zerologon, CVE-2020-1472).
- **Catalog handoff (do not edit `../crypto-lab`):** proposed chip `AES-CFB`, implemented. It
  matches the existing `tools/catalog-vocab.js` term. The existing chips stay.

## Do not touch

`src/ofb.ts`, `src/ofbBroken.ts`, the OFB mutation script and its evidence file, the legacy
theme toggle, the CCM known answers, the padding oracle, the forbidden-attack exhibit and its
`data-verdict` markers, and the header.

## Sources

Each was checked by the brief author and re-checked by an independent reviewer, except where
marked.

- M. Dworkin, NIST SP 800-38A, *Recommendation for Block Cipher Modes of Operation*, December
  2001. §6.3 (CFB). Appendix F.3 was **not read**; see Tests.
- NIST CSRC, "Examples with Intermediate Values", `AES_CFB.pdf`: ciphertext values only.
- D. Poddebniak et al., "Efail: Breaking S/MIME and OpenPGP Email Encryption using Exfiltration
  Channels", 27th USENIX Security Symposium, 2018:
  - §3.2: malleability gadgets; CFB garbles the following block;
  - §5.3.1: the CFB gadget in OpenPGP;
  - the MDC discussion: "The MDC is only effective if it is checked".
- T. Tervoort, "Zerologon: Unauthenticated domain controller compromise by subverting Netlogon
  cryptography", Secura whitepaper, September 2020: the zero-IV and 1-in-256 quotations above.
- `@noble/ciphers` 2.4.0 `aes.js`: exports `cfb` (CFB-128).
- Paar & Pelzl, *Understanding Cryptography* (1st ed., 2010), §5.1.4: teaching context only.
