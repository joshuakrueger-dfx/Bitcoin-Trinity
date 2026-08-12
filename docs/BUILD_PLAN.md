# Build plan — how to take a work package from OPEN to DONE

**Audience:** an executing agent (or developer) implementing packages from
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md). Not the product owner.

**Companion documents (do not restate them here):**

| Document | Role |
|---|---|
| [`SPECIFICATION.md`](SPECIFICATION.md) | What is built and why — **wins every conflict** |
| [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) | Which package delivers what; WP blocks; rules R1–R9 |
| [`UX_CONCEPT.md`](UX_CONCEPT.md) | App surface for M6 packages |
| [`TESTING.md`](TESTING.md) | Environment, coverage policy, CI stages, test naming |
| [`RECOVERY.md`](RECOVERY.md) | User recovery path; target of S5/S6 |

This file is **execution knowledge**: branch order, commands, counter-probes, waves,
crate recipes, and how to notice self-deception. It is deliberately longer than the
specification.

---

## 1 · Standing and relation to the other documents

If this handbook and the specification disagree, **the specification wins**. Change the
spec first (rule **R3**), with justification in the PR, then the code — never the reverse
and never silently.

If this handbook and the implementation plan disagree on a package boundary, acceptance
criterion, or dependency, that is a **blocker**, not a style choice (**R9**). Stop and
report; do not pick a reading and continue.

This document does **not** invent test IDs, decisions, threats, or package scopes. It only
says how to execute what those documents already define.

---

## 2 · The loop for one work package

Same sequence for every WP. Commands are those this repository actually defines
(`justfile`, `.github/workflows/ci.yml`).

### 1. Read

1. The full WP block in `IMPLEMENTATION_PLAN.md` (`**Spec:**`, `**Needs:**`, `**State:**`,
   description, `**Files:**`, `**Prohibited:**`, `**Acceptance**`, `**Tests:**`).
2. Every Spec section named in `**Spec:**`.
3. For **M6** packages (WP-60 … WP-68): also `UX_CONCEPT.md`.
4. If a named Spec section still carries an `⟨API-VERIFY⟩` mark: **stop**. Do not invent
   signatures (**R4**). Resolution is WP-05 / Appendix B, not improvisation.

Confirm `**Needs:**` are met (or already `DONE` / otherwise actually available). If a
dependency is still open and you cannot finish without it, leave this package or mark
`BLOCKED` with the reason — do not implement around the gap.

### 2. Branch (R1)

From the default branch:

```bash
git checkout main   # or the repo default
git pull --ff-only
git checkout -b wp/<id>-<shortname>
```

Examples: `wp/11-descriptor`, `wp/33-signer`, `wp/07-ci-execute`. One WP = one branch =
one PR.

### 3. Test first when a test ID exists (R2)

If `**Tests:**` is not `—`:

1. Name the function after `TESTING.md` §6: lowercase ID, then underscore, then a short
   slug — `d1_…`, `p5_…`, `s29h_…` (no leading zero on the number).
2. Place it under the crate or test tree that the WP's `**Files:**` allow.
3. Run it **before** the production change exists. It must be **red**. Capture the
   failure (command + relevant output). A test that is green before the implementation is
   not proof of anything for that WP.
4. Only then implement.

If `**Tests:**` is `—` (scaffolding, research, CI diagnosis), there is no test-ID
obligation; acceptance criteria and local gates still apply.

### 4. Implement

- Touch only paths listed under `**Files:**`.
- Honour every line under `**Prohibited:**`.
- Do not expand the file list quietly. If the list is too narrow to meet acceptance,
   stop and report (see §7).

### 5. Counter-probes (§4 of this document)

For every test ID you own, run the class-appropriate counter-probe (D, P, or S). Without
it the test is theatre. Restore the correct implementation afterward; leave the
counter-probe evidence in the PR description (what you mutated, that it went red, that
the real code is green again).

### 6. Local gates (§6 of this document)

Run the full local sequence in §6. Fix until every step exits 0 with the stated success
criterion (for lint: **empty diagnostic output**, not “no errors”).

### 7. Open the PR (R7)

PR description must name:

- the **WP-ID**,
- the **Spec sections**,
- the **test IDs** (or explicit `Tests: —`).

Include counter-probe notes and any residual risks.

### 8. State transitions

| When | State |
|---|---|
| You start work | `IN PROGRESS` |
| PR open, waiting review/merge | `REVIEW` |
| **After merge to the default branch** | `DONE` |

Do **not** set `DONE` before merge. Once a package is `DONE`, `scripts/check_plan.py`
requires a real test function for every assigned test ID and fails the build if any is
missing.

---

## 3 · Waves — what may run in parallel

Dependencies are the `**Needs:**` lines in `IMPLEMENTATION_PLAN.md` only. Nothing below
adds edges. Depth is “1 + max depth of needs”; packages in the same wave share the same
depth and may proceed in parallel **when their needs are already satisfied**.

**Critical path (content → release):**

`WP-00 → WP-02 → WP-05 → WP-10 → WP-11 → WP-12 → … → WP-22 → WP-33 → WP-36 → WP-40 → WP-41/WP-42 → WP-43 → WP-60 → … → WP-76`

Parallel side chains join later: **M2** (verify) joins at WP-33; **M5** (hardware) fans out
from WP-33; **WP-04 → WP-75** feeds the release checklist; **WP-07** does not appear on the
code path but until it lands **no CI gate is evidence**.

| Wave | Packages | Satisfied needs | Unlocks / frees |
|---|---|---|---|
| **0** | `WP-00` (DONE), `WP-06` (REVIEW), `WP-07` (OPEN) | — | Workspace; base shell decision path; **CI that actually runs** |
| **1** | `WP-01`, `WP-02`, `WP-04` | WP-00 | CI scaffold content; test env; vendoring / offline build |
| **2** | `WP-03`, `WP-05`, `WP-75` | WP-01; WP-02; WP-04 | Coverage/mutants gates; **Appendix B / ⟨API-VERIFY⟩** (M1–M5 content); repro-build check |
| **3** | `WP-10` | WP-05 | Shared types for M1, M2, M3 |
| **4** | `WP-11`, `WP-20`, `WP-30` | WP-10 | Descriptor; verify parser; entropy |
| **5** | `WP-12`, `WP-21`, `WP-31` | prior wave | Watch wallet; BIP-32/67; blob format |
| **6** | `WP-13`, `WP-22`, `WP-32` | prior wave | Chain trait; V1–V10; keystore |
| **7** | `WP-14`, `WP-15`, `WP-16`, `WP-23`, `WP-33`, `WP-70` | WP-13 / WP-22+WP-02 / WP-32+WP-22 / WP-20+WP-22+WP-31 | Backends; differential harness; **signer**; fuzz entry |
| **8** | `WP-34`, `WP-36`, `WP-50` | WP-33 | SpendPolicy; finalize/broadcast; hardware transport trait |
| **9** | `WP-35`, `WP-40`, `WP-51`–`WP-54` | WP-34 / WP-36 / WP-50 | Passphrase path; FFI; QR/NFC/BIP-388/allowlist |
| **10** | `WP-41`, `WP-42` | WP-40 | iOS + Android keystore layers |
| **11** | `WP-43`, `WP-74` | WP-41+WP-42 / WP-40+WP-41+WP-42 | One-gesture; external audit window |
| **12** | `WP-44`, `WP-45`, `WP-46`, `WP-60` | WP-43 (+ WP-06 for WP-60) | Hygiene; signet harness; export; app scaffold |
| **13** | `WP-61`–`WP-68`, `WP-71`, `WP-72` | WP-60 / WP-46 | UX flows; interop; RECOVERY verification |
| **14** | `WP-73` | WP-61 | User test |
| **15** | `WP-76` | WP-70 … WP-75 | Release checklist (all 21 criteria) |

**Today’s practical first OPEN wave:** `WP-07` (no needs), `WP-04` (needs WP-00 only), and
`WP-05` once WP-02 is far enough that the spike can finish (formal need: **WP-02**). Together
they free measurable CI, vendoring/repro work, and the research that unblocks M1–M5.

**Do not** start WP-10 while WP-05 still leaves architecture-touching `⟨API-VERIFY⟩` marks
open. **Do not** start WP-33 before both WP-32 and WP-22 are done.

---

## 4 · Counter-probes by test class

Three classes of IDs appear in the Spec and on WP `**Tests:**` lines. Each proves something
different. A green run without the matching counter-probe is not acceptance.

### D — Differential against Bitcoin Core

| | |
|---|---|
| **Proves** | This implementation matches an **independent** reference (Core 30.2 RPCs / behaviour) on the cases under test. |
| **Does not prove** | That the reference is ideal, that untested edges work, or that property/scenario guarantees hold. |
| **Counter-probe** | Deliberately **corrupt** the local implementation (wrong checksum, swapped sort order, off-by-one derivation, altered sighash) and show that Core **disagrees** — the test fails because expected ≠ actual. If the test still passes, it is not comparing what you think (or is comparing two copies of the same bug). |

Run D-tests with the harness and Core from WP-02/WP-23 (`just diff-test` once the feature
exists). Never claim differential green without a runner that talks to Core.

### P — Property

| | |
|---|---|
| **Proves** | An invariant holds over **random** inputs under a fixed seed (`PROPTEST_RNG_SEED` in CI). |
| **Does not prove** | Agreement with Core, end-to-end UX, or that a specific production path is wired. |
| **Counter-probe** | Mutate the **invariant** in a plausible-false way that still compiles: `AND`→`OR`, `>`→`>=`, swap expected bounds, invert a rejection. Show the property test goes **red**. Deleting the function body only proves the test was invoked, not that it checks semantics. |

Prefer one surgical mutation per claim. If every test in the suite dies with a compile
error, you measured a crash, not the invariant.

### S — Scenario

| | |
|---|---|
| **Proves** | An **end-to-end** flow behaves as specified (limits, recovery, FFI surface, backends). |
| **Does not prove** | Bit-identity with Core, or exhaustive random coverage. |
| **Counter-probe** | Remove the **assertion that is the point** of the scenario and show the test goes red. Examples: for **S9** and **S28**, drop the mock assertion that `unwrap_kek` was **not** called; if the test stays green, it never enforced the security property. |

Hardware and device scenarios (see `TESTING.md` §4) need real devices for the claim that
matters; protocol-level injection alone is not enough for display/firmware claims.

### Two standing rules

1. **Coverage is not the gate; mutation testing is** (`TESTING.md` §3.3). Line coverage
   shows a path ran; surviving mutants show a path was not checked. Security cores:
   `trinity-verify`, `trinity-signer`, `trinity-keystore`, `trinity-entropy` — no
   surviving mutants without a justified exclusion entry.
2. **A suite that does not compile counts zero tests.** Always compare **suite count and
   test count**, not only “green”. A compile error can drop an entire suite so that fewer
   tests run while the summary still looks clean. Unexpected green is an **alarm** (§7),
   not a success.

---

## 5 · Recipes per crate

What to stand up first, hard dependency bans already fixed in `deny.toml` / WP blocks, and
which packages own acceptance. No new bans invented here.

### `trinity-types` (WP-10)

- **First:** value types with no I/O — `KeySlot`, `Network`, `PsbtB64`, `Fingerprint`,
  `WordCount`, `XpubWithOrigin`, `Balance`, `AddressInfo`, `PsbtVerdict`, `SendRequest`.
- **Internal only:** `SecretBytes` (`ZeroizeOnDrop`, no `Clone`, no real `Debug`/`Display`).
- **Must not:** I/O crates; keystore/signer access; export `SecretBytes` via uniffi.
- **Accepts:** trybuild / compile-fail for `Clone`; coverage gate for this crate from birth
  (R6). No D/P/S IDs on WP-10 itself — later WPs import the types.

### `trinity-watch` (WP-11, WP-12, parts of WP-36)

- **First:** descriptor build/persist (`wsh(sortedmulti(2,…))`, BIP-48, separate
  receive/change — O8), then wallet/UTXO/`TxBuilder`.
- **KeychainKind:** `External` = receive descriptor `/0/*`, `Internal` = change `/1/*`
  (BDK 3.1.0 `types.rs:24`; Spec §1.1 / §2.3).
- **Build in tests:** finish PSBTs with `finish_with_aux_rand` and a fixed seed
  (Spec §3.2; TESTING.md §2.4). Production may use `finish()` (wraps `thread_rng`).
  Signature path (§3.4) is unchanged.
- **Iterators:** BDK `list_unspent` / `list_output` / `transactions` return
  lifetime-bound iterators — collect into `Vec` before any FFI export.
- **Must not:** multipath descriptors; keystore/signer dependencies (`[bans]`).
- **BDK signatures (B.1):** resolved 2026-08-10 from pinned crate source. Kyoto (B.3) and
  Keychain uninstall (B.4) also resolved 2026-08-11 — WP-05 no longer blocks WP-10+ on any
  v1-relevant Appendix B item.
- **Accepts:** D1, P5, P7, P9 (WP-11); D2, D3, D6, P8 (WP-12).

### `trinity-chain` (WP-13 … WP-16)

- **First:** `ChainBackend` trait + in-memory fake (no network in unit tests).
- **Then:** Electrum, Core RPC, CBF backends — each without silent fallback.
- **Must not:** set CBF as default while Appendix B.3 / O3 is open.
- **Accepts:** S13 (Electrum failure path); balance parity contributes to S2 (WP-45).

### `trinity-verify` (WP-20 … WP-22; harness WP-23)

- **First:** grammar-only parser for `wsh(sortedmulti(2,·,·,·))`, then own CKDpub / BIP-67,
  then checks V1–V10.
- **Must not:** **`miniscript`** (direct dep banned; E2 / `deny.toml`). No keystore/signer.
- **Accepts:** D4, D5 (WP-23); P1–P3, P11, P12 (WP-22). Differential harness is WP-23
  (`tests/differential/`, feature `differential`).

### `trinity-entropy` (WP-30)

- **First:** `HMAC-SHA512` construction from OS CSPRNG + optional extra bytes; class A
  encodings; word-count rules (C fixed 24).
- **Must not:** mandatory extra entropy; keystore; I/O beyond entropy sources.
- **Decision:** O13 before expanding source set beyond the decided scope.
- **Accepts:** D12, D13, D17, P10, P14–P16, S15b, S20.

### `trinity-keystore` (WP-31, WP-32, parts of WP-35)

- **First:** blob layout (XChaCha20-Poly1305, header AAD, `word_count`); then
  `PlatformKeyStore` callback, slot policies.
- **Must not:** **`log` / `tracing`** (`deny.toml` + WP-32); plaintext entropy in logs;
  secrets without `ZeroizeOnDrop`; `print!` / `dbg!`.
- **Accepts:** P6, P13 (blob); mock call counts enable S9/S28 in signer WPs.

### `trinity-signer` (WP-33 … WP-36)

- **First:** `Signer` / `LocalSigner`, RFC-6979, low-s, `SIGHASH_ALL`, verify-before-key.
- **Then:** SpendPolicy window, passphrase authorization path, finalize/broadcast
  (BIP-67 witness order, consensus check — O7).
- **Must not:** RNG on the sign path; seed export; non-ALL sighash; policy enforced only
  in JS; rate fetch at sign time.
- **Accepts:** D7, D8, P4, S9, S10; S28–S29j; D16 and S29c–S36 on the passphrase WP;
  D10, D11, S11, S12 on finalization.

### `trinity-ffi` (WP-40)

- **First:** uniffi facade exactly per Spec 1.3; `ffi-allowlist.toml`;
  `scripts/check_ffi_boundary.py`.
- **Must not:** extend the allowlist outside WP-40 without second review (R5); export
  seed/mnemonic/xpriv; export `sign_a`/`sign_b`; export `SecretBytes` type.
- **Accepts:** S23 (build-breaking surface check).

### `trinity-transport` (WP-50 … WP-54)

- **First:** `PsbtTransport` trait; software B remains default.
- **Then:** QR (BBQr/UR), NFC, BIP-388 registration, device allowlisting.
- **Must not:** private material on the wire; BLE as a v1 requirement (O14 is v1.1 order).
- **Accepts:** D19; S26; D18, S16, S18; D9, S17, S21, S22 as assigned.

### `trinity-export` (WP-46; BIP-388 pieces with transport)

- **First:** export formats that RECOVERY.md / Sparrow / Core can consume — no secrets.
- **Must not:** private keys or passphrase in export files.
- **Accepts:** D14, D15, S5, S6.

---

## 6 · Local checks before every PR

Run in this order. Success means **exit code 0** and the criterion in the right-hand
column. Prefer `just <recipe>` where defined; equivalent raw commands match CI.

| # | Command | Success criterion |
|---|---|---|
| 1 | `cargo fmt --all -- --check` | Exit 0; **empty output** (no files need formatting). “No errors” with a diff is still failure. |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings` | Exit 0; **empty diagnostic output** — any warning fails (`-D warnings`, same as CI). |
| 3 | `cargo build --workspace --locked` | Exit 0; lockfile respected, no network surprise. |
| 4 | `cargo test --workspace --locked` | Exit 0; compare **suite count and test count** to the last known baseline when changing tests. |
| 5 | `python3 -m unittest discover -s scripts/tests -p 'test_*.py'` | Exit 0; workflow/inventory/dep-budget/compose gate tests green. |
| 6 | `python3 scripts/check_plan.py` | Exit 0; zero findings (IDs ↔ WPs, inventory baseline, states, number checks). |
| 7 | `python3 scripts/dep_budget.py` | Exit 0; signature-path budget holds (shipped-target union). |
| 8 | `just coverage` when measuring coverage | Exit 0 after `cargo llvm-cov …` and `coverage_gate.py` — once the crate has real code under test. |

Same commands as CI fast path / tools:

- `just check` → `fmt-check`, `clippy`, `build`, `gate-tests`, `check-plan`, `dep-budget`
- `just test` → `cargo test --workspace --locked`
- `just coverage` → llvm-cov + gate (heavy)
- `just mutants` → mutation testing on security cores (heavy; also on `main` in CI)
- `just diff-test` / `just signet-test` when those features exist (heavy)

**Machine load:** do not fire the full heavy suite (coverage, mutants, signet, differential,
fuzz) on every save. Use them when the WP owns that gate or before merge to the default
branch. Cap workers if the machine is a daily driver; prefer targeted `-p <crate>` while
iterating.

---

## 7 · What to do when stuck

**R9, spelled out:** a contradiction between two documents is a **blocker**. Stop. Report
both citations (file + section/line). Do not choose the reading that makes coding easier.
Resolution follows **R3** (spec first when behaviour is in dispute).

Further hard stops:

| Situation | Action |
|---|---|
| `⟨API-VERIFY⟩` in a section you need | Do not guess APIs. Finish or wait on WP-05 / Spec update. |
| Unexpected green test | Alarm. Re-check that the test runs the new code, that counts did not drop, and that a counter-probe still turns it red. |
| `**Files:**` too narrow for acceptance | Do not secretly expand scope. Report; planner widens the WP or splits work. |
| `**Prohibited:**` vs a “helpful” dependency | Prohibition wins. Find another design or escalate. |
| CI green locally, never on GitHub | Track under **WP-07**; local green does not replace runner evidence. |
| Need a decision from §7 of the Spec (O…) | Do not silently pick. Package stays blocked or implements only the decided default already written in the Spec. |

---

## 8 · Effort, honestly

Estimates only — **ranges**, not calendar dates or person-days. Drivers named so the next
reader can revise the range when a driver moves.

| Wave / band | Rough span | What drives the span |
|---|---|---|
| Wave 0–2 (M0 remainder: CI execute, vendoring, spike, finish env/gates) | **Days to a few weeks** | WP-07 may be minutes (account toggle) or blocked on billing/access you do not control; WP-05 is research and Spec edits for 8 open Appendix B items; WP-02 image digests and multi-OS env; WP-04 vendor size and offline proof |
| Wave 3–7 (types through first signer + backends + verify) | **Weeks to a small number of months** | BDK API verification quality; own verify stack without miniscript; differential harness stability; entropy encoding edge cases |
| Wave 8–11 (policy, FFI, platform, one-gesture) | **Weeks+** | Real device behaviour (enclave, biometrics); S27 single-prompt constraint; FFI allowlist discipline |
| Wave 8–9 side (M5 hardware) | **Highly variable** | Physical devices, firmware versions, NFC/QR camera rig; BLE (O14) explicitly out of v1 order |
| Wave 12–15 (app UX, harnesses, audit, release) | **Weeks+; audit not self-scheduled** | WP-06 product choice; external audit (O11) calendar; S4/S5/S6 recovery evidence; user test |

**Not estimable from the repo alone:** account-side CI unlock (WP-07), courier time for
hardware, auditor availability, and any open Spec decision that the owner has not closed.

---

## 9 · Start conditions per milestone

Derived from `**Needs:**`, the blocker table in the plan §4, and open decisions. “Start”
means first production WP of that milestone — not idle reading.

### M1 — Watch-only core (WP-10 … WP-16)

- **WP-05 / B.1:** BDK marks affecting **1.1 / 1.6 / 3.2** are **resolved** (2026-08-10).
  Remaining WP-05 work is B.3 (Kyoto peers), B.4 (Keychain uninstall), B.10–B.14 —
  none of those block the BDK wallet API shape for WP-12.
- **WP-10** needs WP-05; do not open WP-11+ until types exist.
- O8 / O10 defaults are already written in the Spec; do not reopen them in code.
- Tests that build PSBTs use `finish_with_aux_rand` with a fixed seed (§3.2).

### M3 — Keys and signature (WP-30 … WP-36)

- **WP-10** done (types).
- **O13** decided before WP-30 expands entropy sources (blocker table).
- **WP-22** done before **WP-33** (signer needs verify).
- **WP-32** done before WP-33.

### M4 — Platform and FFI (WP-40 … WP-46)

- **WP-36** done before WP-40.
- Passphrase FFI shape from Appendix B.2 already fixed (borrowed `&[u8]`); implement that,
  do not re-litigate.
- Platform WPs need real device or documented simulator gaps per `TESTING.md` §3.1.

### M5 — Hardware signer (WP-50 … WP-54)

- **WP-33** done (transport plugs into signer).
- Device bench available for claims that require it (`TESTING.md` §4).
- **O14** (BLE order) does not block v1 QR/NFC path; it blocks v1.1 ordering only.

### M6 — App and UX (WP-60 … WP-68)

- **WP-43** and **WP-06** done (one-gesture + base shell decision merged).
- **O6** (crash reporting) decided before WP-60 embeds a reporter.
- Follow `UX_CONCEPT.md` for screens; Spec for security-sensitive copy and flows.

### M7 — Hardening and release (WP-70 … WP-76)

- Fuzz inputs need **WP-20, WP-22, WP-31**.
- Interop / RECOVERY checks need **WP-46**.
- User test needs **WP-61**.
- Audit needs **WP-40, WP-41, WP-42** (and O11 timing: before v1.0).
- Repro-build verification needs **WP-04**.
- **WP-76** only when WP-70 … WP-75 are done and all **21** criteria in Spec §5.5 can be
  evidenced — which requires **WP-07** so CI results are real, not aspirational.

### M0 reminder

M0 is not complete until WP-01 … WP-07 meet acceptance (WP-00 is already DONE). Local green
scripts without a runner job (WP-07) leave differential, coverage, mutants, and signet as
statements of intent only.
