# BTC Trinity

Bitcoin-only 2-of-3 multisig wallet. Three equal keys, no timelock, no
state, no server services, no ongoing maintenance.

| Key | Storage | Unlock factor | Backup |
|---|---|---|---|
| **A** | encrypted blob, KEK hardware-bound (Keychain / Android Keystore), `.biometryCurrentSet` | biometrics | deliberately none |
| **B** | encrypted blob, KEK hardware-bound, `.userPresence` | biometrics **or** device passcode | word list, mandatory |
| **C** | seed on paper/steel, offline — or generated on a hardware signer | — | is itself the backup |

> **The passphrase decrypts nothing.** Since decision E7 it no longer enters KEK_B
> — it **authorizes** spending above the spending limit, every relaxation of the policy,
> export, and key rotation. What that costs and what takes its place is in
> Section 2.4 of the specification; the consequence for the user is below under "How it
> should feel".

Script: `wsh(sortedmulti(2, ...))` on BIP-48 paths (`m/48'/0'/0'/2'`), three independent
master seeds.

## Standard

The goal is to be clearly safer than what the user had before — exchange or
single-sig on the phone. **Not** to match a multisig of three hardware wallets in three
places. From that: friction is a cost item, not a
security measure. Anyone who abandons onboarding does not end up with a slightly
less secure wallet, but stays where a single mistake means total loss.

Section 0.1 of the specification spells this out.

## How it should feel

A send costs **one gesture**. One biometric evaluation opens A and B; above that
sits a spending limit enforced in the Rust core, above which the passphrase
becomes unavoidable:

    Without passphrase per 24 h:  clamp( 20 % of balance , €200 , €500 )

In practice: **€200 per day without passphrase; with larger balance up to €500.**

| Balance | without passphrase per 24 h |
|---|---|
| under €1,000 | €200 |
| €1,000 – €2,500 | €200 – €500, sliding |
| over €2,500 | €500 |

No per-transaction limit — that achieves nothing, because a thief simply splits. Floor and
cap are converted to sats once when set; **only the stored sat value is
enforced**, so no exchange rate sits on the signature path and the limit holds offline
too. Raising requires the passphrase; lowering does not.

From that follows the property a common software wallet does not have:

> If your unlocked phone is snatched, the thief gets at most €200 per day — with
> larger holdings a fifth, but never more than €500. For everything above that they need
> the passphrase.
> You take your backup of B, get C from the second storage place, and move the
> rest into a fresh setup — with exactly the two keys the thief does not have.

With single-sig the same incident is total loss with no course of action.

**And if you forget the passphrase:** no loss of funds. Below the limit you keep
sending; for everything above you take the path in `docs/RECOVERY.md` with word lists B and C.
So it does not go stale, the app asks for it once every 60 days — without a transaction,
deferrable.

## Status

Specification phase complete. Milestone M0 has started: workspace with ten
crate scaffolds, CI pipeline and gate scripts are in place; domain logic has not yet begun
(WP-00 done, WP-01 through WP-03 in progress, WP-04 and WP-05 open).

**→ [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md)** — full technical specification:
module cut, key lifecycle, signature flow, threat model, test strategy,
UX flows, open decisions.

**→ [`docs/RECOVERY.md`](docs/RECOVERY.md)** — recovery **without** this app, with
Sparrow and Bitcoin Core. That is the real insurance: it works even when
this project no longer exists. The flows in it are the target test cases S5
(automated in CI planned) and S6 (manual against Sparrow each release). Today
none of these tests exist yet — they are acceptance of WP-46 and WP-71.

**→ [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md)** — the work list.
54 work packages in 8 milestones, each with dependencies, spec reference, acceptance criteria
and the tests that must be green. Each package is cut so it can be worked
without follow-up questions.

**→ [`docs/TESTING.md`](docs/TESTING.md)** — test environment, coverage policy, CI pipeline.
100 % lines and branches for the security cores, mutation testing as the real gate,
exceptions only with justification in a checked-in file.

**→ [`docs/BUILD_PLAN.md`](docs/BUILD_PLAN.md)** — execution handbook for taking a work package
from `OPEN` to `DONE`: branch rules, test-first loop, counter-probes, waves, local gates.

Specification, plan, testing, and recovery docs are checked against each other by
`just check-plan`: every test ID has exactly one work package, every decision has an
implementing package, every section reference points to an existing section. If that runs
red, the plan is incomplete.

Before implementation starts: resolve the 14 points in Appendix B of the specification — that is
WP-05 and blocks milestones M1 through M5.

## What this model does not cover

Explicit and readable in Section 4.2 of the specification:

- **Compromised phone** — A and B live on one device.
- **Theft with observed passphrase** — device + passphrase yield the quorum.
- **Backup B and C in the same place** — the one rule the user must keep and that
  the app cannot check.
- **Coercion.**
- **Supply-chain attack on the app** — reduced, not excluded, as long as A and B
  share the same implementation.
