# BTC Trinity

Bitcoin-only 2-von-3 Multisig-Wallet. Drei gleichberechtigte Schlüssel, kein Timelock, kein
Zustand, keine Serverdienste, keine laufende Wartung.

| Schlüssel | Speicherort | Entsperrfaktor |
|---|---|---|
| **A** | verschlüsselter Blob, Schlüssel hardware-gebunden (Keychain / Android Keystore) | Biometrie |
| **B** | verschlüsselter Blob, Schlüssel hardware-gebunden ⊕ Argon2id(Passphrase) | Passphrase |
| **C** | Seed auf Papier/Stahl, offline | — |

Script: `wsh(sortedmulti(2, ...))` auf BIP-48-Pfaden (`m/48'/0'/0'/2'`), drei unabhängige
Master-Seeds.

## Maßstab

Ziel ist, deutlich sicherer zu sein als das, was der Nutzer vorher hatte — Börse oder
Single-Sig auf dem Handy. **Nicht**, mit einem Multisig aus drei Hardware-Wallets an drei
Orten gleichzuziehen. Daraus folgt: Reibung ist eine Kostenposition, keine
Sicherheitsmaßnahme. Wer das Onboarding abbricht, landet nicht bei einer etwas
unsichereren Wallet, sondern bleibt dort, wo ein einziger Fehler Totalverlust bedeutet.

Abschnitt 0.1 der Spezifikation führt das aus.

## Status

Spezifikationsphase. Es existiert noch kein Code.

**→ [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md)** — vollständige technische Spezifikation:
Modulschnitt, Schlüssel-Lebenszyklus, Signaturfluss, Bedrohungsmodell, Teststrategie,
UX-Flows, offene Entscheidungen.

Vor Implementierungsbeginn zu klären: die sechs Entscheidungen in der Executive Summary
und die ⟨API-VERIFY⟩-Punkte in Anhang B der Spezifikation.

## Was dieses Modell nicht abdeckt

Ausdrücklich und nachlesbar in Abschnitt 4.2 der Spezifikation:

- **Kompromittiertes Telefon** — A und B liegen auf einem Gerät.
- **Diebstahl mit beobachteter Passphrase** — Gerät + Passphrase ergeben das Quorum.
- **Backup-B und C am selben Ort** — die eine Regel, die der Nutzer einhalten muss und die
  die App nicht prüfen kann.
- **Nötigung.**
- **Supply-Chain-Angriff auf die App** — reduziert, nicht ausgeschlossen, solange A und B
  dieselbe Implementierung teilen.
