# App-shell basis decision

**Measurement date:** 2026-08-09 · **Branch:** `spike/app-basis` · **Kind:** spike, no build

---

## 1. The question

On which existing foundation do we build the app shell (navigation, onboarding,
send and receive screens, QR, address book, settings), instead of writing it from scratch?
The wallet core is not the subject of this question.

---

## 2. What is not up for debate

1. **The Rust core stays.** `bdk_wallet` + `uniffi` are set in §0.3, §1.1 and §1.3.
   `bdk-ffi` shows that this build form exists in production. Swapping the core for
   a JavaScript wallet library is excluded.

2. **Decision E1 / §1.3 stays hard.** The only type that may cross the trust boundary
   toward Rust is `SecretBytes` from the **native** layer. A seed
   as a JavaScript string is forbidden. §0.1 names exactly this pattern as a negative example.

3. **`nunchuk-android` is out without case-by-case review.** The `LICENSE` file is
   GNU GPL-3.0. §1.7 and release criterion 9b exclude project-wide copyleft.

---

## 3. Comparison table

Four rows. Every number is measured; where not measurable, it says "not measured".

| # | Criterion | (a) Null variant | (b) WDK shell | (c) BlueWallet as template | (d) Nunchuk |
|---|---|---|---|---|---|
| **K1** | License (`LICENSE` file) | n/a (no upstream) | Apache-2.0 (`wdk-starter-react-native`, `wdk-uikit-react-native`, `wdk-react-native-core`) | MIT | **GPL-3.0 — excluded** |
| **K2** | Keys in the JS heap | No upstream code; shell starts empty | **Yes.** Starter passes mnemonic as JS `string` via router params; Core/Pear hold seed in Bare worklet (JS). Wallet half takes `seed: string \| Uint8Array` in the constructor. | **Yes.** `AbstractWallet.secret: string`; `MultisigHDWallet._cosigners` stores xpubs **or** mnemonic phrases as `string[]`. | eliminated |
| **K3** | Shell without wallet half | Everything self-built (0 inherited) | Route screens: **2** without wallet marker / **17** with (of **19**). Components: **11** generic UI / **4** seed-/wallet-related. UIKit: **8** UI components + theme, of which `SeedPhrase` with `words: string[]`. | Screens under `screen/`: **82**. Multisig-specific: **15**. Without wallet classes and without `screen/wallets` navigation/settings scaffold remains, but no runnable flow. | eliminated |
| **K4** | Dependency load | Template `expo-template-blank-typescript`: **4** `dependencies`, **2** `devDependencies`. Lockfile total: **not measured** (upstream ships no `package-lock.json`; `npm install` was forbidden). | Starter: **46** deps, lockfile **1108** packages. UIKit: **2** deps, lock **1125**. Core: **8** deps, lock **1202**. | **99** deps, lockfile **1569** packages. | eliminated |
| **K5** | Reload paths (§1.7) | Template: no CodePush/OTA/remote-config packages in `package.json` | In the three shell `package.json` files: **no** CodePush, no `expo-updates`, no remote-config service. (Bare worklet is not OTA, but a second JS runtime — see K6.) | In `package.json`: **no** CodePush/`expo-updates`/remote-config. Present: `@bugsnag/react-native` (crash reporting, not OTA; spec-relevant for O6). | eliminated |
| **K6** | Bindability to Rust/uniffi | Expo/RN: config plugins and native modules common; empty base, no competition | Expo plugins and `modules/` present. **But:** `wdk-react-native-core` hangs on `@tetherto/pear-wrk-wdk` and `react-native-bare-kit` — second JS wallet runtime with seed in the worklet. Coexistence with our Rust core: technically possible, architecturally competing (two secret holders). | Bare RN with `ios/`/`android/`, codegen native modules (`codegen/`, Swift/Kotlin). uniffi bindings attachable. No Bare-kit competition. | eliminated |
| **K7** | Liveness (GitHub API, 90 days from 2026-05-11) | n/a | Starter: last commit **2026-08-06**, **4** commits/90d, **1** open issue. UIKit: **2026-08-03**, **8**/90d, **2** issues. Core: **2026-08-04**, **37**/90d, **4** issues. | Last commit **2026-08-08**, **232** commits/90d, **416** open issues. | Last commit **2026-08-05**, **253**/90d, **57** issues — for orientation only; row remains excluded. |
| **K8** | Cost of gutting | **0** files to remove | Count method: source files in the starter that import wallet stack or call seed APIs: **22** files. Additionally **15** wallet-/chain-/bare-related `dependencies` entries in the starter. Core without Pear is not the published package — gutting Core would mean a fork. | Count method: (1) files with `setSecret`/`getSecret`/`mnemonic`/`bip39` outside tests/loc: **32**; (2) `class/` **37** files; (3) `screen/wallets` **33**; (4) full TS/JS tree without node_modules/Pods: **447**. Gutting ≈ large parts of (2)+(3) plus binding. | eliminated |
| **K9** | Upstream binding | **Assessment:** none. | **Assessment:** Usable as one-time copy or thin fork of the UI; upstream updates to Core/Pear pull the secret stack and collide with E1. | **Assessment:** Template/copy of individual screens feasible; full fork expensive (232 commits/90d, 416 issues). Upstream contribution unlikely (different architecture). | eliminated |

### Briefly on (d)

`nunchuk-android/LICENSE` starts with "GNU GENERAL PUBLIC LICENSE Version 3". That ends
the comparison for this row.

---

## 4. The hard test

> **Does the trust boundary from §1.3 remain intact if we take over this shell?**

### Favoured row: (a) Null variant

**Yes — by construction.** There is no inherited code path that creates seed, xpriv or
passphrase as a JavaScript value. The shell starts empty; everything secret only arises
in what we ourselves bind under `platform/` and `crates/trinity-ffi`. The boundary from
§1.3 is not inherited and not violated as long as WP-40/WP-60 keep the allowlist and the native
input fields.

### (b) WDK shell — no, unless one cuts out X, Y, Z

Measured:

| What | Evidence |
|---|---|
| Mnemonic as router `string` | `wdk-starter-react-native/src/app/(onboarding)/seed-hidden.tsx` lines 31–32: `const mnemonic = await generateSeed(wordCount)` → `params: { mnemonic }` |
| Mnemonic in password route | `…/password.tsx` line 26: `mnemonic?: string` from `useLocalSearchParams`; line 49: `await importWallet(mnemonic)` |
| Import builds JS string | `…/import.tsx` lines 36–37: `words…join(' ')` → `importWallet(mnemonic)` |
| Repository type | `…/data/repositories/types.ts` line 9: `createWallet(): Promise<{ mnemonic: string[] }>` |
| Wallet constructor (half, excluded but wired in starter) | `wdk-wallet-btc/src/wallet-manager-btc.js` lines 34–38: `constructor (seed, config = {})` with `seed` as BIP-39 phrase; `wallet-account-btc.js` lines 105–111: `typeof seed === 'string'` → `bip39.mnemonicToSeedSync(seed)` |
| Pear worklet holds keys in JS | `pear-wrk-wdk/README.md`: worklet "holds the private keys in memory"; `src/handlers/secrets.js` lines 23–25, 60–66, 74–75: mnemonic as `string`, "cannot be zeroed" |
| Core hangs on Pear | `wdk-react-native-core/package.json`: dependency `@tetherto/pear-wrk-wdk`; `workletLifecycleService.ts` among others `getMnemonicFromEntropy` → `{ mnemonic: string }` |
| UIKit seed UI | `wdk-uikit-react-native/src/SeedPhrase.tsx` lines 20–21: `words: string[]` in React state |

**X, Y, Z by name:**

- **X** — entire seed lifecycle in JS: onboarding routes (`seed-hidden`, `seed-revealed`,
  `import`, `password` with mnemonic param), `SeedWord*` / `SeedPhrase`, repository API with
  `mnemonic: string[]`.
- **Y** — `@tetherto/wdk-react-native-core` including `@tetherto/pear-wrk-wdk`,
  `react-native-bare-kit`, `bare-node-runtime` and the bundled worklet
  (`.wdk-bundle/…`): the second secret runtime.
- **Z** — all `@tetherto/wdk-wallet-*`, `@tetherto/wdk` (orchestrator), secret/backup paths
  (`wdk-react-native-secure-storage` as seed vault, cloud backup with seed export).

After removing X+Y+Z, Expo-router scaffold, theme and generic UI widgets remain.
That is close to the null variant, plus foreign lockfile and Tether branding — without the
gain that would justify the takeover.

**Addendum:** `multisig` / `sortedmulti` in `wdk-wallet-btc`: **0** hits. Hits on
"descriptor" concern Electrum/Blockbook **client** descriptors, not output descriptors
for multisig. The wallet half does not cover the product anyway.

### (c) BlueWallet — no, unless one guts the wallet core

Measured:

| What | Evidence |
|---|---|
| Secret as `string` | `class/wallets/abstract-wallet.ts` line 55: `this.secret = '' // private key or recovery phrase`; lines 217–234: `getSecret(): string` / `setSecret(newSecret: string)` |
| Multisig stores seeds | `class/wallets/multisig-hd-wallet.ts` line 83: `_cosigners: string[]` "xpubs or mnemonic seeds"; lines 241–242, 368–373: `bip39.validateMnemonic` / `mnemonicToSeedSync` |
| sortedmulti present | same file from line 607: parsing of `sortedmulti(` |
| Multisig UI real | **15** files under `screen/` with Multisig/PSBT hardware in the name; class `MultisigHDWallet` |

**X, Y, Z by name:**

- **X** — `class/wallets/**` and `class/wallet-import.ts` (entire secret holding in JS).
- **Y** — onboarding/import/export/PleaseBackup and all screens that touch `setSecret` /
  mnemonics (among others Multisig-Provide-Mnemonics sheets).
- **Z** — Electrum/LN/Ark stack and persistence (Realm among others) that hang on the JS wallet model.

What remains **worth reading** as a template afterwards: multisig flow order, PSBT-with-hardware UI,
settings structure. That is a UX reference, not a takeable shell under E1.

### (d) Nunchuk

Not reviewed beyond the license. GPL-3.0.

### Conclusion of the hard test

For **(b)** and **(c)** the answer to the §1.3 question is: **no**, as long as the
secret stack stays in; **yes only after gutting**, which largely destroys the part worth taking over.
For **(a)** it is **yes**. The null variant wins the hard
test — and thus the comparison if one holds E1 non-negotiable.

---

## 5. Recommendation

**Recommendation: (a) Null variant** — empty React Native/Expo scaffold in WP-60, domain UI and
native secret inputs built ourselves, binding exclusively to our own Rust core via
uniffi.

**Rationale (short):**

1. E1 fails on WDK and BlueWallet without surgical removal of exactly the parts that create the
   "finished wallet" impression.
2. After that gutting, WDK leaves measurably little shell (2/19 route screens without
   wallet marker; Core without Pear is a different product). With BlueWallet a large
   foreign codebase remains with 99 direct dependencies and 1569 lockfile packages that one would have to keep
   carrying or keep cutting out.
3. The null variant has the lowest dependency load at start (4 template dependencies),
   no second JS secret runtime and no license or upstream binding on the
   app path.

**What speaks against the recommendation:**

- M6 costs more build time: onboarding, QR, address book, multisig coordination, hardware-PSBT UI
  and settings do not come from a finished flow.
- BlueWallet is the only candidate that **already** has 2-of-3 multisig screens and
  hardware-PSBT surfaces; that quality must be rebuilt under the null variant from Spec §6 and from
  reading BlueWallet **as reference** (not as codebase).
- WDK delivers a fresh Expo-55 scaffold, theme and UI kit; that saves hours on day one,
  not the architecture decision.

**What is expressly not recommended:** WDK shell "without wallet half" as product base.
The half sits in Core/Pear, not only in `wdk-wallet-*`. BlueWallet fork as app base
under E1 likewise not.

**Allowed, limited use without choosing a base:** individual screen flows and
naming patterns from BlueWallet (and UI look from WDK-UIKit) as **read reference**
during WP-61–WP-68 — without a dependency in `package.json` and without a copied secret path.

---

## 6. When a revision becomes expensive

| Point in time | Cost of a U-turn |
|---|---|
| Until completion of WP-06 / before WP-60 | **cheap** — only this document and the plan |
| During WP-60 (scaffold) | **medium** — `app/` scaffold new, still little UX |
| From WP-61 (onboarding) and WP-62 (native dialog) | **expensive** — flows, navigation and native bridges are wired |
| After parallel completion of WP-63–WP-68 | **rebuild of the app shell** — core (M0–M5) remains, everything under `app/` and parts of `platform/` UI binding not |

Making the decision now costs no application code. Making it after M6
costs the M6 stack.

---

## 7. What was not measured

- Live installing the candidates (`npm install` / Metro / Xcode / Gradle) — forbidden
  in the brief; lockfile numbers come from the **checked-in** lockfiles of the clones.
- Lockfile package count of the Expo null variant after `create-expo-app` (upstream template without
  lockfile; install forbidden).
- Runtime behaviour, memory profiles, whether seeds appear in crash dumps of the candidates
  (static code evidence only).
- Full transitive license review of the npm trees with a `cargo-deny` equivalent for JS
  (only root `LICENSE` of the repos and package names in `package.json`).
- Whether BlueWallet's Bugsnag actively sends telemetry by default in builds (package present;
  configuration/default not runtime-checked).
- Exact diff "WDK-Core without Pear" as a hypothetical fork (not built).
- `Foundation-Devices/envoy` and other non-comparison rows from the brief context
  (not in the four rows).
- Accessibility, i18n quality, UI test coverage of the candidates.
- Coexistence Bare-kit + uniffi in the same process (architecture reading of the READMEs only, no
  link attempt).
- Whether future WDK versions add multisig (as of clone 2026-08-09: no).
- Human UX assessment of the screens (count and code paths only).

---

## 8. Measurement protocol (commands)

Clones: `git clone --depth 1` to `/tmp/basis-spike/` for the named repos on 2026-08-09.

| Measurement | Command (core) | Result |
|---|---|---|
| K1 licenses | `head` on `LICENSE` per repo | Apache-2.0 / MIT / GPL-3.0 as table |
| K2 WDK seed | `rg` + file reading `wallet-manager-btc.js`, onboarding, `secrets.js` | see §4 |
| K2 BlueWallet | reading `abstract-wallet.ts`, `multisig-hd-wallet.ts` | `secret: string`, cosigner mnemonics |
| K3 WDK routes | 19 files under `src/app` without `_layout`; classification by import/seed marker | 2 / 17 |
| K3 BlueWallet screens | `find screen -type f … \| wc -l` | 82; Multisig name: 15 |
| K4 deps | `len(package.json["dependencies"])` | 4 (template) / 46 / 99 |
| K4 lock | `len(package-lock["packages"])-1` (lockfileVersion 3) | 1108 / 1125 / 1202 / 1569 |
| K5 | `package.json` keys against CodePush/OTA/remote-config patterns | no hits in deps |
| K7 | GitHub API `commits?since=2026-05-11`, Search Commits `total_count`, Repo `open_issues_count` | see table |
| K8 WDK | source files with wallet-stack import | 22 files; 15 dep entries |
| K8 BlueWallet | `rg -l setSecret\|mnemonic\|bip39` excl. tests/loc | 32 files; class 37; screen/wallets 33 |

---

## 9. References

- Specification: §0.1, §1.3 (E1), §1.7, assumption A2, Section 6 (UX)
- Plan: **WP-06** (this spike result), cut of **WP-60…WP-68** depending on the choice
- Kernel evidence (not a candidate): `bitcoindevkit/bdk-ffi` — architecture evidence, not a
  shell substitute
