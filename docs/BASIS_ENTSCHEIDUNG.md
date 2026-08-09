# Basis-Entscheidung App-Schale

**Stand der Messung:** 2026-08-09 · **Zweig:** `spike/app-basis` · **Art:** Spike, kein Bau

---

## 1. Die Frage

Auf welcher bestehenden Grundlage bauen wir die App-Schale (Navigation, Onboarding,
Sende- und Empfangsscreens, QR, Adressbuch, Einstellungen), statt sie von null zu
schreiben? Der Wallet-Kern ist nicht Gegenstand dieser Frage.

---

## 2. Was nicht zur Debatte steht

1. **Der Rust-Kern bleibt.** `bdk_wallet` + `uniffi` sind in §0.3, §1.1 und §1.3 gesetzt.
   `bdk-ffi` belegt, dass diese Bauform produktiv existiert. Ein Tausch des Kerns gegen
   eine JavaScript-Wallet-Bibliothek ist ausgeschlossen.

2. **Entscheidung E1 / §1.3 bleibt hart.** Der einzige Typ, der die Vertrauensgrenze
   Richtung Rust überqueren darf, ist `SecretBytes` aus der **nativen** Schicht. Ein Seed
   als JavaScript-String ist verboten. §0.1 nennt genau dieses Muster als Negativbeispiel.

3. **`nunchuk-android` ist ohne Einzelfallprüfung raus.** Die `LICENSE`-Datei ist
   GNU GPL-3.0. §1.7 und Freigabekriterium 9b schließen Projekt-Copyleft aus.

---

## 3. Vergleichstabelle

Vier Zeilen. Jede Zahl ist gemessen; wo nicht messbar, steht „nicht gemessen".

| # | Kriterium | (a) Nullvariante | (b) WDK-Schale | (c) BlueWallet als Vorlage | (d) Nunchuk |
|---|---|---|---|---|---|
| **K1** | Lizenz (`LICENSE`-Datei) | n. a. (kein Upstream) | Apache-2.0 (`wdk-starter-react-native`, `wdk-uikit-react-native`, `wdk-react-native-core`) | MIT | **GPL-3.0 — ausgeschlossen** |
| **K2** | Schlüssel im JS-Heap | Kein Upstream-Code; Schale startet leer | **Ja.** Starter reicht Mnemonic als JS-`string` über Router-Params; Core/Pear halten Seed im Bare-Worklet (JS). Wallet-Hälfte nimmt `seed: string \| Uint8Array` im Konstruktor. | **Ja.** `AbstractWallet.secret: string`; `MultisigHDWallet._cosigners` speichert xpubs **oder** Mnemonic-Phrasen als `string[]`. | ausgeschieden |
| **K3** | Schale ohne Wallet-Hälfte | Alles selbst (0 geerbt) | Route-Screens: **2** ohne Wallet-Marker / **17** mit (von **19**). Komponenten: **11** generische UI / **4** seed-/wallet-bezogen. UIKit: **8** UI-Komponenten + Theme, davon `SeedPhrase` mit `words: string[]`. | Screens unter `screen/`: **82**. Multisig-spezifisch: **15**. Ohne Wallet-Klassen und ohne `screen/wallets` bleibt Navigation/Settings-Gerüst, aber kein lauffähiger Flow. | ausgeschieden |
| **K4** | Abhängigkeitslast | Template `expo-template-blank-typescript`: **4** `dependencies`, **2** `devDependencies`. Lockfile-Gesamtzahl: **nicht gemessen** (Upstream liefert kein `package-lock.json`; `npm install` war verboten). | Starter: **46** deps, Lockfile **1108** Pakete. UIKit: **2** deps, Lock **1125**. Core: **8** deps, Lock **1202**. | **99** deps, Lockfile **1569** Pakete. | ausgeschieden |
| **K5** | Nachladewege (§1.7) | Template: keine CodePush/OTA/Remote-Config-Pakete in `package.json` | In den drei Schalen-`package.json`: **kein** CodePush, kein `expo-updates`, kein Remote-Config-Dienst. (Bare-Worklet ist kein OTA, aber eine zweite JS-Laufzeit — siehe K6.) | In `package.json`: **kein** CodePush/`expo-updates`/Remote-Config. Vorhanden: `@bugsnag/react-native` (Crash-Reporting, nicht OTA; spez-relevant für O6). | ausgeschieden |
| **K6** | Anbindbarkeit an Rust/uniffi | Expo/RN: Config-Plugins und native Module üblich; leere Basis, keine Konkurrenz | Expo-Plugins und `modules/` vorhanden. **Aber:** `wdk-react-native-core` hängt an `@tetherto/pear-wrk-wdk` und `react-native-bare-kit` — zweite JS-Wallet-Laufzeit mit Seed im Worklet. Koexistenz mit unserem Rust-Kern: technisch möglich, architektonisch konkurrierend (zwei Secret-Halter). | Bare RN mit `ios/`/`android/`, Codegen-Native-Module (`codegen/`, Swift/Kotlin). uniffi-Bindings einhängbar. Keine Bare-Kit-Konkurrenz. | ausgeschieden |
| **K7** | Lebendigkeit (GitHub-API, 90 Tage ab 2026-05-11) | n. a. | Starter: letzter Commit **2026-08-06**, **4** Commits/90d, **1** offenes Issue. UIKit: **2026-08-03**, **8**/90d, **2** Issues. Core: **2026-08-04**, **37**/90d, **4** Issues. | Letzter Commit **2026-08-08**, **232** Commits/90d, **416** offene Issues. | Letzter Commit **2026-08-05**, **253**/90d, **57** Issues — nur zur Einordnung; Zeile bleibt ausgeschlossen. |
| **K8** | Kosten des Entkernens | **0** Dateien zu entfernen | Zählmethode: Quelldateien im Starter, die Wallet-Stack importieren oder Seed-APIs rufen: **22** Dateien. Zusätzlich **15** wallet-/chain-/bare-bezogene `dependencies`-Einträge im Starter. Core ohne Pear ist nicht das veröffentlichte Paket — Entkernen von Core hieße Fork. | Zählmethode: (1) Dateien mit `setSecret`/`getSecret`/`mnemonic`/`bip39` außerhalb Tests/loc: **32**; (2) `class/` **37** Dateien; (3) `screen/wallets` **33**; (4) gesamter TS/JS-Baum ohne node_modules/Pods: **447**. Entkernen ≈ große Teile von (2)+(3) plus Anbindung. | ausgeschieden |
| **K9** | Upstream-Bindung | **Einschätzung:** keine. | **Einschätzung:** Nutzbar als einmalige Kopie oder dünner Fork der UI; Upstream-Updates an Core/Pear ziehen Secret-Stack nach und kollidieren mit E1. | **Einschätzung:** Vorlage/Copy einzelner Screens machbar; voller Fork teuer (232 Commits/90d, 416 Issues). Rückfluss in Upstream unwahrscheinlich (andere Architektur). | ausgeschieden |

### Kurz zu (d)

`nunchuk-android/LICENSE` beginnt mit „GNU GENERAL PUBLIC LICENSE Version 3". Damit endet
der Vergleich für diese Zeile.

---

## 4. Die harte Prüfung

> **Bleibt die Vertrauensgrenze aus §1.3 unversehrt, wenn wir diese Schale übernehmen?**

### Favorisierte Zeile: (a) Nullvariante

**Ja — by construction.** Es gibt keinen übernommenen Codepfad, der Seed, xpriv oder
Passphrase als JavaScript-Wert anlegt. Die Schale startet leer; alles Geheime entsteht erst
in dem, was wir selbst unter `platform/` und `crates/trinity-ffi` anbinden. Die Grenze aus
§1.3 wird nicht geerbt und nicht verletzt, solange WP-40/WP-60 die Allowlist und die nativen
Eingabefelder einhalten.

### (b) WDK-Schale — nein, außer man operiert X, Y, Z heraus

Gemessen:

| Was | Beleg |
|---|---|
| Mnemonic als Router-`string` | `wdk-starter-react-native/src/app/(onboarding)/seed-hidden.tsx` Zeilen 31–32: `const mnemonic = await generateSeed(wordCount)` → `params: { mnemonic }` |
| Mnemonic in Password-Route | `…/password.tsx` Zeile 26: `mnemonic?: string` aus `useLocalSearchParams`; Zeile 49: `await importWallet(mnemonic)` |
| Import baut JS-String | `…/import.tsx` Zeilen 36–37: `words…join(' ')` → `importWallet(mnemonic)` |
| Repository-Typ | `…/data/repositories/types.ts` Zeile 9: `createWallet(): Promise<{ mnemonic: string[] }>` |
| Wallet-Konstruktor (Hälfte, ausgeschlossen aber im Starter verdrahtet) | `wdk-wallet-btc/src/wallet-manager-btc.js` Zeilen 34–38: `constructor (seed, config = {})` mit `seed` als BIP-39-Phrase; `wallet-account-btc.js` Zeilen 105–111: `typeof seed === 'string'` → `bip39.mnemonicToSeedSync(seed)` |
| Pear-Worklet hält Schlüssel in JS | `pear-wrk-wdk/README.md`: Worklet „holds the private keys in memory"; `src/handlers/secrets.js` Zeilen 23–25, 60–66, 74–75: Mnemonic als `string`, „cannot be zeroed" |
| Core hängt an Pear | `wdk-react-native-core/package.json`: Dependency `@tetherto/pear-wrk-wdk`; `workletLifecycleService.ts` u. a. `getMnemonicFromEntropy` → `{ mnemonic: string }` |
| UIKit Seed-UI | `wdk-uikit-react-native/src/SeedPhrase.tsx` Zeilen 20–21: `words: string[]` in React State |

**X, Y, Z namentlich:**

- **X** — gesamter Seed-Lifecycle in JS: Onboarding-Routen (`seed-hidden`, `seed-revealed`,
  `import`, `password` mit Mnemonic-Param), `SeedWord*` / `SeedPhrase`, Repository-API mit
  `mnemonic: string[]`.
- **Y** — `@tetherto/wdk-react-native-core` samt `@tetherto/pear-wrk-wdk`,
  `react-native-bare-kit`, `bare-node-runtime` und dem gebündelten Worklet
  (`.wdk-bundle/…`): die zweite Secret-Laufzeit.
- **Z** — alle `@tetherto/wdk-wallet-*`, `@tetherto/wdk` (Orchestrator), Secret-/Backup-Pfade
  (`wdk-react-native-secure-storage` als Seed-Tresor, Cloud-Backup mit Seed-Export).

Nach Entfernen von X+Y+Z bleiben Expo-Router-Gerüst, Theme und generische UI-Widgets.
Das ist nah an der Nullvariante, plus Fremd-Lockfile und Tether-Branding — ohne den
Gewinn, der die Übernahme rechtfertigen würde.

**Zusatz:** `multisig` / `sortedmulti` in `wdk-wallet-btc`: **0** Treffer. Treffer auf
„descriptor" betreffen Electrum/Blockbook-**Client**-Deskriptoren, keine Output-Descriptoren
für Multisig. Die Wallet-Hälfte deckt das Produkt ohnehin nicht.

### (c) BlueWallet — nein, außer man operiert den Wallet-Kern heraus

Gemessen:

| Was | Beleg |
|---|---|
| Secret als `string` | `class/wallets/abstract-wallet.ts` Zeile 55: `this.secret = '' // private key or recovery phrase`; Zeilen 217–234: `getSecret(): string` / `setSecret(newSecret: string)` |
| Multisig speichert Seeds | `class/wallets/multisig-hd-wallet.ts` Zeile 83: `_cosigners: string[]` „xpubs or mnemonic seeds"; Zeilen 241–242, 368–373: `bip39.validateMnemonic` / `mnemonicToSeedSync` |
| sortedmulti vorhanden | dieselbe Datei ab Zeile 607: Parsing von `sortedmulti(` |
| Multisig-UI real | **15** Dateien unter `screen/` mit Multisig/PSBT-Hardware im Namen; Klasse `MultisigHDWallet` |

**X, Y, Z namentlich:**

- **X** — `class/wallets/**` und `class/wallet-import.ts` (gesamte Secret-Haltung in JS).
- **Y** — Onboarding/Import/Export/PleaseBackup und alle Screens, die `setSecret` /
  Mnemonics anfassen (u. a. Multisig-Provide-Mnemonics-Sheets).
- **Z** — Electrum-/LN-/Ark-Stack und Persistenz (Realm u. a.), die am JS-Wallet-Modell hängen.

Was danach als Vorlage **lesenswert** bleibt: Multisig-Flow-Reihenfolge, PSBT-mit-Hardware-UI,
Settings-Gliederung. Das ist UX-Referenz, keine übernehmbare Schale unter E1.

### (d) Nunchuk

Nicht geprüft jenseits der Lizenz. GPL-3.0.

### Folgerung der harten Prüfung

Für **(b)** und **(c)** lautet die Antwort auf die §1.3-Frage: **nein**, solange der
Secret-Stack drin bleibt; **ja nur nach Entkernung**, die den übernahmewerten Teil
weitgehend vernichtet. Für **(a)** lautet sie **ja**. Die Nullvariante gewinnt die harte
Prüfung — und damit den Vergleich, wenn man E1 nicht verhandelbar hält.

---

## 5. Empfehlung

**Empfehlung: (a) Nullvariante** — leeres React-Native-/Expo-Gerüst in WP-60, Fach-UI und
native Secret-Eingaben selbst bauen, Anbindung ausschließlich an den eigenen Rust-Kern über
uniffi.

**Begründung (kurz):**

1. E1 scheitert bei WDK und BlueWallet ohne chirurgische Entfernung genau der Teile, die den
   „fertigen Wallet"-Eindruck erzeugen.
2. Nach diesem Entkernen bleibt bei WDK messbar wenig Schale (2/19 Route-Screens ohne
   Wallet-Marker; Core ohne Pear ist ein anderes Produkt). Bei BlueWallet bleibt eine große
   fremde Codebasis mit 99 direkten Dependencies und 1569 Lockfile-Paketen, die man weiter
   mitschleppen oder weiter herausschneiden müsste.
3. Die Nullvariante hat die geringste Abhängigkeitslast am Start (4 Template-Dependencies),
   keine zweite JS-Secret-Laufzeit und keine Lizenz- oder Upstream-Bindung auf dem
   App-Pfad.

**Was gegen die Empfehlung spricht:**

- M6 kostet mehr Bauzeit: Onboarding, QR, Adressbuch, Multisig-Koordination, Hardware-PSBT-UI
  und Settings entstehen nicht aus einem fertigen Flow.
- BlueWallet hat als einziger Kandidat **bereits** 2-von-3-Multisig-Screens und
  Hardware-PSBT-Oberflächen; diese Qualität muss bei Nullvariante aus Spec §6 und aus dem
  Lesen von BlueWallet **als Referenz** (nicht als Codebasis) neu gebaut werden.
- WDK liefert frisches Expo-55-Gerüst, Theme und UI-Kit; das spart am ersten Tag Stunden,
  nicht die Architekturentscheidung.

**Was ausdrücklich nicht empfohlen wird:** WDK-Schale „ohne Wallet-Hälfte" als Produktbasis.
Die Hälfte sitzt in Core/Pear, nicht nur in `wdk-wallet-*`. BlueWallet-Fork als App-Basis
unter E1 ebenso nicht.

**Zulässige, begrenzte Nutzung ohne Basis-Wahl:** einzelne Bildschirmabläufe und
Bezeichnungs-Muster aus BlueWallet (und UI-Anmutung aus WDK-UIKit) als **Lese-Referenz**
während WP-61–WP-68 — ohne Abhängigkeit im `package.json` und ohne kopierten Secret-Pfad.

---

## 6. Wann eine Revision teuer wird

| Zeitpunkt | Kosten einer Kehrtwende |
|---|---|
| Bis Abschluss WP-06 / vor WP-60 | **billig** — nur dieses Dokument und der Plan |
| Während WP-60 (Gerüst) | **mittel** — `app/`-Gerüst neu, noch wenig UX |
| Ab WP-61 (Onboarding) und WP-62 (nativer Dialog) | **teuer** — Flows, Navigation und native Brücken sind verdrahtet |
| Nach parallel fertigen WP-63–WP-68 | **Neubau der App-Schale** — Kern (M0–M5) bleibt, alles unter `app/` und Teile von `platform/` UI-Anbindung nicht |

Die Entscheidung jetzt zu treffen kostet keinen Anwendungscode. Sie nach M6 zu treffen
kostet den M6-Stack.

---

## 7. Was nicht gemessen wurde

- Laufendes Installieren der Kandidaten (`npm install` / Metro / Xcode / Gradle) — verboten
  im Auftrag; Lockfile-Zahlen stammen aus den **eingecheckten** Lockfiles der Clones.
- Lockfile-Paketzahl der Expo-Nullvariante nach `create-expo-app` (Upstream-Template ohne
  Lockfile; Install verboten).
- Laufzeitverhalten, Speicherprofile, ob Seeds in Crash-Dumps der Kandidaten erscheinen
  (nur statischer Codebeleg).
- Vollständige transitive Lizenzprüfung der npm-Bäume mit `cargo-deny`-Äquivalent für JS
  (nur Root-`LICENSE` der Repos und Paketnamen in `package.json`).
- Ob BlueWallets Bugsnag in Builds standardmäßig aktiv Telemetrie sendet (Paket vorhanden;
  Konfiguration/Default nicht Laufzeit-geprüft).
- Exactes Diff „WDK-Core ohne Pear" als hypothetischer Fork (nicht gebaut).
- `Foundation-Devices/envoy` und andere Nicht-Vergleichszeilen aus dem Auftragskontext
  (nicht in den vier Zeilen).
- Barrierefreiheit, i18n-Qualität, Testabdeckung der UI der Kandidaten.
- Koexistenz Bare-Kit + uniffi im selben Prozess (nur Architektur-Lesung der READMEs, kein
  Link-Versuch).
- Ob künftige WDK-Versionen Multisig nachrüsten (Stand Clone 2026-08-09: nein).
- Menschliche UX-Bewertung der Screens (nur Zählung und Codepfade).

---

## 8. Messprotokoll (Befehle)

Clones: `git clone --depth 1` nach `/tmp/basis-spike/` für die genannten Repos am 2026-08-09.

| Messung | Befehl (Kern) | Ergebnis |
|---|---|---|
| K1 Lizenzen | `head` auf `LICENSE` je Repo | Apache-2.0 / MIT / GPL-3.0 wie Tabelle |
| K2 WDK seed | `rg` + Dateilesen `wallet-manager-btc.js`, Onboarding, `secrets.js` | siehe §4 |
| K2 BlueWallet | Lesen `abstract-wallet.ts`, `multisig-hd-wallet.ts` | `secret: string`, cosigner-Mnemonics |
| K3 WDK Routes | 19 Dateien unter `src/app` ohne `_layout`; Klassifikation per Import-/Seed-Marker | 2 / 17 |
| K3 BlueWallet Screens | `find screen -type f … \| wc -l` | 82; Multisig-Name: 15 |
| K4 deps | `len(package.json["dependencies"])` | 4 (Template) / 46 / 99 |
| K4 lock | `len(package-lock["packages"])-1` (lockfileVersion 3) | 1108 / 1125 / 1202 / 1569 |
| K5 | `package.json`-Keys gegen CodePush/OTA/Remote-Config-Muster | keine Treffer in deps |
| K7 | GitHub API `commits?since=2026-05-11`, Search Commits `total_count`, Repo `open_issues_count` | siehe Tabelle |
| K8 WDK | Quelldateien mit Wallet-Stack-Import | 22 Dateien; 15 dep-Einträge |
| K8 BlueWallet | `rg -l setSecret\|mnemonic\|bip39` exkl. tests/loc | 32 Dateien; class 37; screen/wallets 33 |

---

## 9. Bezug

- Spezifikation: §0.1, §1.3 (E1), §1.7, Annahme A2, Abschnitt 6 (UX)
- Plan: **WP-06** (dieses Spike-Ergebnis), Zuschnitt **WP-60…WP-68** abhängig von der Wahl
- Kernel-Beleg (nicht Kandidat): `bitcoindevkit/bdk-ffi` — Architekturbeleg, kein
  Schalen-Ersatz
