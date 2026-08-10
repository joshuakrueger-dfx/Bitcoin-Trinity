# BTC Trinity

Bitcoin-only 2-von-3 Multisig-Wallet. Drei gleichberechtigte Schlüssel, kein Timelock, kein
Zustand, keine Serverdienste, keine laufende Wartung.

| Schlüssel | Speicherort | Entsperrfaktor | Backup |
|---|---|---|---|
| **A** | verschlüsselter Blob, KEK hardware-gebunden (Keychain / Android Keystore), `.biometryCurrentSet` | Biometrie | bewusst keines |
| **B** | verschlüsselter Blob, KEK hardware-gebunden, `.userPresence` | Biometrie **oder** Gerätepasscode | Wortliste, Pflicht |
| **C** | Seed auf Papier/Stahl, offline — oder auf einem Hardware-Signer erzeugt | — | ist selbst das Backup |

> **Die Passphrase entschlüsselt nichts.** Seit Entscheidung E7 geht sie nicht mehr in KEK_B
> ein — sie **autorisiert** Ausgaben oberhalb der Ausgabegrenze, jede Lockerung der Policy,
> Export und Schlüsseltausch. Was das kostet und was an ihre Stelle tritt, steht in
> Abschnitt 2.4 der Spezifikation; die Folge für den Nutzer steht unten unter „Wie es sich
> anfühlen soll".

Script: `wsh(sortedmulti(2, ...))` auf BIP-48-Pfaden (`m/48'/0'/0'/2'`), drei unabhängige
Master-Seeds.

## Maßstab

Ziel ist, deutlich sicherer zu sein als das, was der Nutzer vorher hatte — Börse oder
Single-Sig auf dem Handy. **Nicht**, mit einem Multisig aus drei Hardware-Wallets an drei
Orten gleichzuziehen. Daraus folgt: Reibung ist eine Kostenposition, keine
Sicherheitsmaßnahme. Wer das Onboarding abbricht, landet nicht bei einer etwas
unsichereren Wallet, sondern bleibt dort, wo ein einziger Fehler Totalverlust bedeutet.

Abschnitt 0.1 der Spezifikation führt das aus.

## Wie es sich anfühlen soll

Ein Sendevorgang kostet **eine Geste**. Eine biometrische Auswertung öffnet A und B; darüber
liegt eine im Rust-Kern durchgesetzte Ausgabegrenze, oberhalb derer die Passphrase
unumgehbar wird:

    Ohne Passphrase pro 24 h:  clamp( 20 % des Guthabens , 200 € , 500 € )

In der Praxis: **200 € am Tag ohne Passphrase, bei größerem Guthaben bis zu 500 €.**

| Guthaben | ohne Passphrase pro 24 h |
|---|---|
| unter 1.000 € | 200 € |
| 1.000 – 2.500 € | 200 – 500 €, gleitend |
| über 2.500 € | 500 € |

Keine Grenze pro Transaktion — die bringt nichts, weil ein Dieb einfach stückelt. Sockel und
Deckel werden beim Einstellen einmalig in Sat umgerechnet; **durchgesetzt wird ausschließlich
der gespeicherte Sat-Wert**, damit kein Kurs im Signaturpfad steht und die Grenze auch offline
gilt. Anheben verlangt die Passphrase, senken nicht.

Daraus folgt die Eigenschaft, die ein gängiges Software-Wallet nicht hat:

> Wird dir das entsperrte Telefon entrissen, kommt der Dieb an höchstens 200 € am Tag — bei
> größeren Beständen an ein Fünftel, aber nie an mehr als 500 €. Für alles darüber braucht er
> die Passphrase.
> Du nimmst dein Backup von B, holst C aus dem zweiten Aufbewahrungsort und schiebst den
> Rest in ein frisches Setup — mit genau den zwei Schlüsseln, die der Dieb nicht hat.

Bei Single-Sig ist derselbe Vorfall ein Totalverlust ohne Handlungsoption.

**Und wenn du die Passphrase vergisst:** kein Geldverlust. Unterhalb der Grenze sendest du
weiter; für alles darüber gehst du den Weg aus `docs/RECOVERY.md` mit den Wortlisten B und C.
Damit sie nicht einrostet, fragt die App alle 60 Tage einmal danach — ohne Transaktion,
verschiebbar.

## Status

Spezifikationsphase abgeschlossen. Meilenstein M0 ist angefangen: Workspace mit zehn
Crate-Gerüsten, CI-Pipeline und Gate-Skripte stehen; Fachlogik ist noch nicht begonnen
(WP-00 fertig, WP-01 bis WP-03 in Arbeit, WP-04 und WP-05 offen).

**→ [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md)** — vollständige technische Spezifikation:
Modulschnitt, Schlüssel-Lebenszyklus, Signaturfluss, Bedrohungsmodell, Teststrategie,
UX-Flows, offene Entscheidungen.

**→ [`docs/RECOVERY.md`](docs/RECOVERY.md)** — Wiederherstellung **ohne** diese App, mit
Sparrow und Bitcoin Core. Das ist die eigentliche Versicherung: Sie funktioniert auch dann,
wenn es dieses Projekt nicht mehr gibt. Die Abläufe darin sind die Ziel-Testfälle S5
(automatisiert in CI vorgesehen) und S6 (je Release manuell gegen Sparrow). Heute existiert
noch kein einziger dieser Tests — sie sind Abnahme von WP-46 und WP-71.

**→ [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md)** — die Arbeitsliste.
52 Arbeitspakete in 8 Meilensteinen, jedes mit Abhängigkeiten, Spec-Verweis, Abnahmekriterien
und den Tests, die grün sein müssen. Jedes Paket ist so geschnitten, dass es ohne Rückfragen
abgearbeitet werden kann.

**→ [`docs/TESTING.md`](docs/TESTING.md)** — Testumgebung, Coverage-Politik, CI-Pipeline.
100 % Zeilen und Zweige für die Sicherheitskerne, Mutation Testing als eigentliches Gate,
Ausnahmen nur mit Begründung in einer eingecheckten Datei.

Alle vier Dokumente werden von `just check-plan` gegeneinander geprüft: jede Test-ID hat
genau ein Arbeitspaket, jede Entscheidung hat ein umsetzendes Paket, jeder Abschnittsverweis
zeigt auf einen existierenden Abschnitt. Läuft das rot, ist der Plan unvollständig.

Vor Implementierungsbeginn zu klären: die 14 Punkte in Anhang B der Spezifikation — das ist
WP-05 und blockiert die Meilensteine M1 bis M5.

## Was dieses Modell nicht abdeckt

Ausdrücklich und nachlesbar in Abschnitt 4.2 der Spezifikation:

- **Kompromittiertes Telefon** — A und B liegen auf einem Gerät.
- **Diebstahl mit beobachteter Passphrase** — Gerät + Passphrase ergeben das Quorum.
- **Backup-B und C am selben Ort** — die eine Regel, die der Nutzer einhalten muss und die
  die App nicht prüfen kann.
- **Nötigung.**
- **Supply-Chain-Angriff auf die App** — reduziert, nicht ausgeschlossen, solange A und B
  dieselbe Implementierung teilen.
