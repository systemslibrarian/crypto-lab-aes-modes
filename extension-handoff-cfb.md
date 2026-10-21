# CFB extension handoff

Implemented SP 800-38A CFB-128 and CFB-8 with forward AES for encryption and decryption, complete feedback traces and independent decryption windows, error propagation, deletion/resynchronisation, IV reuse, bounded cancellable zero-IV key search, and the known-block rewrite. UTF-8 block counters and strict length checks are visible. The zero-IV experiment is explicitly a teaching property, not Netlogon; the gadget does not implement OpenPGP’s resynchronisation variant.

Verification: 87 Vitest cases plus 2 publication-command tests; 32 Chromium browser cases across the existing and added exhibits passed. The final CFB-only rerun passed all 11 cases after the UTF-8 counters were added. New states were scanned at 1280px and 320px without baseline expansion. Ten mechanism mutations built, changed the bundle hash, failed their owning assertion with retries disabled, and restored to the exact baseline hash and green test; see mutation-evidence-cfb.json. Chromium was run using the host browser; Firefox/WebKit remain in the committed CI gate and must pass before Pages deploys.

Sources reviewed: NIST SP 800-38A §6.3 and Appendix F, NIST AES_CFB.pdf examples (all four AES-128/256 × CFB-128/8 vectors), EFAIL §§3.2 and 5.3.1. The normal CFB path refuses an all-zero IV, avoids reuse for its current key and retires stale results on real input changes. Existing OFB code and its assertions were preserved.

Catalog follow-up: add CFB-128 and CFB-8 to implemented modes; the concepts are ciphertext feedback, limited error propagation, resynchronisation and confidentiality without integrity. Review the source at the published commit before regenerating derived coverage. Keep OFB and the existing mode coverage intact. This handoff does not edit the catalog.
