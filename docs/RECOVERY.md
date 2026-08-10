# Wiederherstellung ohne diese App

**Dieses Dokument ist die eigentliche Versicherung.** Es beschreibt, wie du an deine Bitcoin
kommst, wenn es diese App nicht mehr gibt, sie nicht mehr startet, dein Telefon weg ist oder
du ihr schlicht nicht mehr vertraust.

Es setzt **nichts** von dieser App voraus. Alles unten funktioniert mit frei verfügbarer
Standardsoftware und Werkzeugen, die auch in zehn Jahren noch existieren werden.

> **Ziel: verifiziert gegen jeden Release.** Die Abläufe hier sind die Testfälle S5 (Bitcoin
> Core, automatisiert in CI vorgesehen) und S6 (Sparrow, je Release manuell verifiziert und
> dokumentiert — siehe `TESTING.md` §2.2 und SPECIFICATION.md §5.3). Heute ist noch kein
> Test implementiert; sobald sie laufen, blockiert ein Fehlschlag die Freigabe
> (`SPECIFICATION.md`, Abschnitt 5.5).

---

## 1. Was du brauchst

| | Was | Woher |
|---|---|---|
| **Pflicht** | Der **Descriptor** | Backup-Ausdruck, `descriptor.json`, BSMS-Datei, oder QR auf dem Ausdruck |
| **Pflicht** | **Zwei** der drei Schlüssel | zwei von: Telefon (A), Wortliste B, Wortliste C |
| Hilfreich | `word_count` je Schlüssel (24 oder 12) | steht auf dem Ausdruck |
| Hilfreich | Die `birthday`-Blockhöhe | steht auf dem Ausdruck; ohne sie dauert der Scan länger |

### Der Descriptor sieht so aus

```
wsh(sortedmulti(2,
  [a1b2c3d4/48h/0h/0h/2h]xpub6C...A/0/*,
  [e5f6a7b8/48h/0h/0h/2h]xpub6D...B/0/*,
  [c9d0e1f2/48h/0h/0h/2h]xpub6E...C/0/*))#checksum
```

Dazu ein zweiter, identischer Descriptor mit `/1/*` statt `/0/*` — das sind die
Wechselgeld-Adressen. **Du brauchst beide.**

> **Kein Descriptor, aber alle drei xpubs mit Origin-Angabe?** Dann kannst du ihn selbst
> zusammensetzen — genau nach obigem Muster. Die **Reihenfolge der drei Schlüssel ist
> egal**, weil `sortedmulti` sie nach BIP-67 selbst sortiert. Die Prüfsumme nach `#`
> berechnet dir Bitcoin Core mit `getdescriptorinfo`.

> ### ⚠️ Weder Descriptor noch der dritte xpub vorhanden?
> Wenn du nur zwei Seeds hast und weder den Descriptor noch den öffentlichen Schlüssel des
> dritten kennst, ist die Wallet **nicht wiederherstellbar**. Es gibt kein Verfahren, den
> fehlenden xpub zu erraten — das ist kryptografisch ausgeschlossen, nicht bloß schwierig.
> **Deshalb liegt der Descriptor auf jedem Backup-Ausdruck.**

---

## 2. Der schnellste Weg: Sparrow

Für die meisten die richtige Wahl — grafisch, kostenlos, quelloffen, für genau diesen Fall
gebaut.

### 2.1 Wallet anlegen (nur beobachtend, noch ohne Schlüssel)

1. Sparrow von [sparrowwallet.com](https://sparrowwallet.com) laden. **Prüfe die Signatur
   der Datei** — die Anleitung dazu steht auf derselben Seite.
2. *File → New Wallet*, Namen vergeben.
3. Policy Type: **Multi Signature**, Script Type: **Native SegWit (P2WSH)**, Quorum **2 of 3**.
4. Descriptor einspielen: unter dem Reiter **Descriptor** die Textbox öffnen, den
   Descriptor hineinkopieren und *Apply* wählen.
5. Sparrow zeigt jetzt drei Schlüssel mit ihren Fingerprints. **Vergleiche die drei
   Fingerprints mit deinem Ausdruck.** Stimmen sie nicht, hast du den falschen Descriptor.
6. Unter *Settings → Server* einen Server wählen — dein eigener Electrum-Server oder Bitcoin
   Core, falls vorhanden. Sonst ein öffentlicher; siehe Hinweis unten.
7. Rechtsklick auf die Wallet → *Rescan* ab der Birthday-Höhe. Dein Guthaben erscheint.

> **Privatsphäre:** Ein öffentlicher Electrum-Server sieht bei diesem Schritt deine
> vollständige Wallet — alle Adressen, alle Beträge, deine IP. Für eine einmalige Rettung ist
> das meist hinnehmbar, für Dauerbetrieb nicht. Wenn du die Wahl hast, nimm einen eigenen
> Server oder Bitcoin Core.

### 2.2 Alles in eine neue Wallet verschieben

An dieser Stelle **immer sweepen** — die alte Aufstellung gilt nach einem Verlust- oder
Diebstahlsfall als möglicherweise kompromittiert.

1. Neue Ziel-Wallet vorbereiten (frisches Setup in dieser App, eine Hardware-Wallet, oder eine
   neue Sparrow-Wallet) und eine Empfangsadresse besorgen.
2. In der wiederhergestellten Wallet: Reiter *Send*, Zieladresse eintragen, **Max** wählen,
   Gebühr setzen, *Create Transaction*.
3. *Finalize Transaction for Signing*. Sparrow zeigt jetzt die unsignierte Transaktion.
4. **Ersten Schlüssel signieren:** Sparrow fragt nach dem Seed. Wortliste eingeben. Es
   erscheint **eine** von zwei nötigen Signaturen.
5. **Zweiten Schlüssel signieren:** denselben Weg mit der zweiten Wortliste. Jetzt sind es
   zwei von zwei.
6. *Broadcast Transaction*.

**Fertig.** Deine Mittel liegen in der neuen Wallet.

> **Bevor du sendest, prüfe die Zieladresse Zeichen für Zeichen** — mindestens die ersten und
> letzten acht. Das ist der Moment, in dem Address Poisoning zuschlägt.

---

## 3. Der Weg ohne grafische Oberfläche: Bitcoin Core

Nutze diesen Weg, wenn du einen eigenen Node hast, keiner fremden Software vertrauen willst,
oder Sparrow eines Tages nicht mehr existiert.

> **Version:** **30.2 oder neuer.** Die Versionen 30.0 und 30.1 hatten einen Fehler, der beim
> Migrieren älterer Wallets Wallet-Dateien löschen konnte; sie wurden von bitcoincore.org
> zurückgezogen. Verwende sie nicht.

### 3.1 Watch-only-Wallet anlegen

```bash
# Descriptor-Wallet ohne private Schlüssel
bitcoin-cli createwallet "rettung" true true "" false true true

# Prüfsummen berechnen lassen (auch wenn du sie hast — Tippfehler fallen hier auf)
bitcoin-cli getdescriptorinfo "wsh(sortedmulti(2,[a1b2c3d4/48h/0h/0h/2h]xpubA/0/*,...))"
```

```bash
# Beide Descriptoren importieren, Empfangen und Wechselgeld.
# "timestamp" ist ein Unix-Zeitstempel (Sekunden seit 1970), kein Blockhöhe.
# Aus der Birthday-Höhe z. B.:
#   bitcoin-cli getblockheader $(bitcoin-cli getblockhash 812345)
# und das Feld "time" übernehmen — hier als Beispiel 1700000000 (Nov 2023).
# Alternativen: 0 (Scan ab Genesis) oder "now" (kein historischer Scan).
bitcoin-cli -rpcwallet=rettung importdescriptors '[
  {"desc":"wsh(sortedmulti(2,...))#pruefsumme1",
   "active":true,"internal":false,"range":[0,1000],"timestamp":1700000000},
  {"desc":"wsh(sortedmulti(2,...))#pruefsumme2",
   "active":true,"internal":true, "range":[0,1000],"timestamp":1700000000}
]'
```

`importdescriptors` erwartet im Feld `timestamp` einen **Unix-Zeitstempel** (oder `0` bzw.
`"now"`). Die Birthday-Angabe auf dem Backup-Ausdruck ist dagegen eine **Blockhöhe**.
Um aus der Höhe den Zeitstempel zu bekommen: `getblockhash <höhe>` und danach
`getblockheader` bzw. `getblockstats` — Feld `time`. Im Zweifel `0`: Core scannt ab Genesis,
das dauert länger, findet aber alles.

```bash
# Kontrolle: stimmen die Adressen mit dem überein, was du erwartest?
bitcoin-cli deriveaddresses "wsh(sortedmulti(2,...))#pruefsumme1" "[0,5]"

# Zusätzlicher Rescan ab Blockhöhe (hier die Birthday-Höhe, nicht der Zeitstempel)
bitcoin-cli -rpcwallet=rettung rescanblockchain 812345
bitcoin-cli -rpcwallet=rettung getbalances
```

### 3.2 Transaktion bauen

```bash
bitcoin-cli -rpcwallet=rettung walletcreatefundedpsbt \
  '[]' '[{"bc1q...zieladresse":0.0}]' 0 \
  '{"subtractFeeFromOutputs":[0],"fee_rate":15}'
```

Ergebnis ist ein PSBT in Base64. **Prüfe es, bevor du signierst:**

```bash
bitcoin-cli decodepsbt "cHNidP8B..."
bitcoin-cli analyzepsbt "cHNidP8B..."
```

Kontrolliere: Geht der Betrag an die richtige Adresse? Ist die Gebühr plausibel? Gibt es
unerwartete Outputs?

### 3.3 Mit beiden Schlüsseln signieren

Signieren ohne die privaten Schlüssel dauerhaft anzulegen — jeder Schlüssel in einer eigenen
Wegwerf-Wallet:

```bash
# Erster Schlüssel
bitcoin-cli createwallet "signer1" false false "" false true true
bitcoin-cli -rpcwallet=signer1 importdescriptors '[{
  "desc":"wsh(sortedmulti(2,[fpA/48h/0h/0h/2h]XPRIV_A/0/*,[fpB/...]xpubB/0/*,[fpC/...]xpubC/0/*))#pruefsumme",
  "active":false,"range":[0,1000],"timestamp":0}]'
bitcoin-cli -rpcwallet=signer1 walletprocesspsbt "cHNidP8B..."

# Zweiter Schlüssel, mit dem Ergebnis aus dem vorigen Schritt
bitcoin-cli createwallet "signer2" false false "" false true true
# ... derselbe Descriptor, aber XPRIV_C statt xpubC
bitcoin-cli -rpcwallet=signer2 walletprocesspsbt "<psbt-aus-schritt-1>"
```

Den `xprv` bekommst du aus deiner Wortliste mit einem BIP-39/BIP-32-Werkzeug — Sparrow zeigt
ihn unter *Tools → Wallet Import*, offline nutzbar.

```bash
# Abschließen und senden
bitcoin-cli finalizepsbt "<psbt-mit-zwei-signaturen>"
bitcoin-cli testmempoolaccept '["<rohe-transaktion-hex>"]'   # zuerst prüfen!
bitcoin-cli sendrawtransaction "<rohe-transaktion-hex>"
```

```bash
# Aufräumen: die Wegwerf-Wallets mit den privaten Schlüsseln entfernen
bitcoin-cli unloadwallet "signer1" && bitcoin-cli unloadwallet "signer2"
# und die Wallet-Verzeichnisse anschließend löschen
```

---

## 4. Häufige Fälle

### Telefon weg, Backups von B und C vorhanden
Der Normalfall. Weg nach Abschnitt 2 oder 3, mit den Wortlisten B und C. Das Telefon wird
nicht gebraucht.

### Telefon vorhanden, ein Backup verloren
Solange die App läuft, hast du A und B auf dem Gerät. Sende alles in ein frisches Setup,
**bevor** noch etwas passiert — ein zweiter Verlust wäre dann endgültig.

### Neuer Fingerabdruck registriert, App meldet Schlüssel A als verloren
Erwartetes Verhalten, kein Fehler: A hängt am Biometrie-Enrollment und wird bei Änderung
zerstört. **B lebt weiter** — sie liegt in einer Zugriffsklasse, die auch der Gerätepasscode
öffnet. Du hast also B auf dem Gerät und C auf Papier, also das Quorum, und kannst direkt in
ein frisches Setup migrieren, ohne die Wortliste von B zu brauchen.

### Passphrase vergessen
**Kein Geldverlust.** Die Passphrase verschlüsselt keinen Schlüssel; sie autorisiert nur
Ausgaben oberhalb der Tagesgrenze und Änderungen an dieser Grenze. Unterhalb der Grenze kannst
du weiter senden. Willst du alles bewegen: Weg nach Abschnitt 2 oder 3 mit den Wortlisten B
und C.

### Ein Schlüssel ist in fremde Hände geraten
Ein Schlüssel allein kann nichts. Aber handle zügig: Erzeuge ein **vollständig neues** Setup
mit drei frischen Schlüsseln und verschiebe alles dorthin, signiert mit den beiden Schlüsseln,
die der Angreifer nicht hat. **Tausche nicht nur den einen Schlüssel im bestehenden
Descriptor** — sonst braucht der Angreifer nur noch einen weiteren.

### Telefon gestohlen, entsperrt, Passphrase unbekannt
Der Dieb kommt an höchstens die Tagesgrenze (Standard: 200 €, bei größeren Beständen bis
500 €). **Hole sofort den Rest weg**: Wortlisten B und C, Weg nach Abschnitt 2, alles in ein
frisches Setup. Du hast die zwei Schlüssel, die er nicht hat.

---

## 5. Prüfe das, bevor du es brauchst

Der einzige Backup-Plan, der zählt, ist der ausprobierte. Empfehlung: einmal nach der
Einrichtung und danach einmal im Jahr.

**Testlauf ohne Risiko:**

1. Descriptor in Sparrow importieren, ohne Schlüssel (Abschnitt 2.1).
2. Prüfen, ob die ersten Empfangsadressen mit denen in der App übereinstimmen. Tun sie das,
   ist dein Descriptor korrekt und lesbar.
3. Einen kleinen Betrag an eine dieser Adressen senden.
4. Ihn mit B und C wieder herausholen — ohne das Telefon anzufassen.

Klappt das, funktioniert deine Wiederherstellung. Klappt es nicht, findest du es zu einem
Zeitpunkt heraus, an dem es nur Zeit kostet.

---

## 6. Merksätze

1. **Der Descriptor ist genauso wichtig wie die Schlüssel.** Der häufigste Totalverlust bei
   Multisig ist nicht der verlorene Schlüssel, sondern der verlorene Descriptor.
2. **Backup von B und Backup von C nie am selben Ort.** Zwei Schlüssel an einem Ort sind das
   Quorum — ein Einbruch wäre dann ein Totalverlust, ganz ohne Kryptografie.
3. **Der Descriptor ist nicht geheim.** Er enthält nur öffentliche Schlüssel. Lege ihn ruhig
   mehrfach ab, auch digital, auch in einer Cloud.
4. **Nach jedem Verlustfall sweepen, nicht weiterbenutzen.**
5. **Zieladresse immer Zeichen für Zeichen prüfen** — mindestens erste und letzte acht.
