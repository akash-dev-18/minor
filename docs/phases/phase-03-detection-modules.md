# Phase 3 — Detection Modules

**Goal:** Five independent security modules with typed findings and honest statuses.

## Modules
1. **URL analysis** — IP-literal hosts, shorteners, encoded/oversized URLs,
   punycode, typosquat indicators, suspicious subdomains, redirect chains behind
   an SSRF guard.
2. **Domain reputation** — DNS existence, RDAP registration data, disposable
   domains, SPF record presence, lookalike/brand impersonation, sender vs
   Reply-To mismatch.
3. **Header analysis** — From/Reply-To/Return-Path, Received chain, Message-ID,
   SPF/DKIM/DMARC interpretation from `Authentication-Results` *treated as
   claims*; statuses `pass|fail|neutral|none|unknown|not_verified`.
4. **Content analysis** — urgency, credential/OTP/payment requests, suspension
   threats, hidden HTML, form detection, anchor-text mismatch.
5. **Attachment analysis** — magic-byte detection, extension mismatch, SHA-256,
   suspicious extensions, size/archive limits, ClamAV adapter (`UNAVAILABLE`).

## Rules
- Each module exposes its own schema and can run standalone.
- Modules never import another module's internals.
- Every result has `module`, `status`, `findings`, `duration_ms`, `error`.
- External failures produce `UNAVAILABLE`, not fabricated findings.
- Rate/size/time limits enforced on every network or file operation.

## Done when
- [x] Each module has passing unit tests in `tests/unit/`.
- [x] A module raising an exception is recorded as `FAILED` without breaking others.
- [x] SSRF and archive guards have dedicated tests.
- [x] Docs and `TASKS.md` updated.
