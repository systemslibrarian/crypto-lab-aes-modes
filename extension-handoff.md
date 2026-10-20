# AES Modes — OFB extension

Brief: `brief-extension.md` (the supplied `extension-crypto-lab-aes-modes.md`).
Repository: `systemslibrarian/crypto-lab-aes-modes`.
Starting main: `e21f33489cc44fd71aa3803eb708d47a0921d987`.
Pages: https://systemslibrarian.github.io/crypto-lab-aes-modes/

The pinned tree matched the brief. No sibling source in the available extension
clones contained OFB or output-feedback code before this implementation. The
existing tab boundary token is `--border-strong`; the new `--control-border`
alias uses it. All seven obsolete 1:1 tab-boundary baseline entries were removed
after fixing the controls, with no new exemptions.

## Delivered

One OFB tab after CTR, and a sixth comparison card. The existing WebCrypto
single-block AES function is exported and reused, with actual per-call counters.
Precomputation, measured block access versus CTR, isolated deliberate IV reuse,
exact bit changes, and unpadded lengths are live computations. Fresh normal
IVs, input refusals, stale-result retirement, and no-op key-size handling are
covered. Existing cipher panels, theme pin, header and deployment workflows remain.

## Evidence

- Build passed; 68 Vitest cases and 2 publishing-request cases passed.
- 21 Chromium browser tests passed, including the full existing accessibility
  state sweep at desktop/380px and the new OFB states at 320px.
- Local browser: Chromium 153.0.8010.0 selected by an untracked config because
  the pinned download endpoint returned an unavailable page. CI keeps its
  original Chromium/Firefox/WebKit gate; deployment evidence is checked separately.
- Two NIST four-block OFB vectors (AES-128/256), all eight intermediate outputs,
  two derived 60-byte truncations, and two direct WebCrypto block pins.
  Primary sources verified: NIST AES_OFB.pdf and SP 800-38A F.4.1/F.4.5 and
  F.1.1/F.1.5. An independent noble ECB route checks every length 0–200.
- §4.1a: boot changes only the panel count; new product assertions belong in claims.
- §4.1b: new `e2e/claims.spec.ts` recomputes the stream via WebCrypto AES-CTR,
  independent of the source's AES-CBC route, and verifies rendered bytes,
  counters, actual access trace rows, overlaps, lengths, status classes and retirement.
  Older panels' missing independent claims coverage remains a separate task.
- §4.1c: 6/6 killed. Each had a committed green baseline, nonempty source patch,
  successful mutant build, moved production digest, named assertion failure with
  zero retries, restored digest and restored green owner test. Reproduce with
  `node scripts/check-ofb-mutations.mjs`; digests and patches are in
  `mutation-evidence.json`. The sixth mutation removes the negative claim.
- §4.1d: PAY 0100 becomes PAY 9100, decryption finishes with the same length and
  valid text, while the alarm explicitly says confidentiality does not authenticate.
- Visual inspection: rendered 320px OFB panel, including its modified-message alarm.

## Catalog handoff (no shared catalog edits)

Card copy suggestion (24 words): “Compare AES modes, precompute an OFB stream,
measure sequential access, and break confidentiality-only encryption through IV
reuse and bit changes. Contrast authenticated modes.”
Chip: add `AES-OFB`; keep existing chips.
Implemented: `ofbKeystream`, `ofbXor`, `ofbDecryptBlock` and counted
`ctrDecryptBlock` in `src/ofb.ts`; isolated two-time-pad recovery in
`src/ofbBroken.ts`. AES itself reuses `src/ecb.ts:ecbEncryptBlock`.
CFB is an extension seam/comment only; not an implemented feature.
Concept deepened: **4. Confusion, diffusion, and cipher structure**.
The README had no numbered Exhibits section; the brief explicitly requested that
it remain absent. What It Is, comparison text, and Correctness & Tests are updated.

Summary: 68 unit + 2 publishing-request + 21 local browser cases passed;
§4.1c 6/6 killed; accessibility gate passed. Final remote SHA and served-byte
verification are recorded in the delivery after publication.
