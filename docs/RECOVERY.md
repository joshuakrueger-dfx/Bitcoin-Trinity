Trinity — serverloses 2-von-3 Wallet-Schema. Entwurf: Joshua Krüger, 2026.

# Recovery without this app

**This document is the real insurance.** It describes how you get to your bitcoin
when this app no longer exists, no longer starts, your phone is gone, or
you simply no longer trust it.

It assumes **nothing** from this app. Everything below works with freely available
standard software and tools that will still exist in ten years.

> **Goal: verified against every release.** The flows here are test cases S5 (Bitcoin
> Core, automated in CI planned) and S6 (Sparrow, manually verified and
> documented each release — see `TESTING.md` §2.2 and SPECIFICATION.md §5.3). Today no
> test is implemented yet; once they run, a failure blocks the release
> (`SPECIFICATION.md`, Section 5.5).

---

## 1. What you need

| | What | Where from |
|---|---|---|
| **Required** | The **descriptor** | backup printout, `descriptor.json`, BSMS file, or QR on the printout |
| **Required** | **Two** of the three keys | two of: phone (A), word list B, word list C |
| Helpful | `word_count` per key (24 or 12) | on the printout |
| Helpful | The `birthday` block height | on the printout; without it the scan takes longer |

### The descriptor looks like this

```
wsh(sortedmulti(2,
  [a1b2c3d4/48h/0h/0h/2h]xpub6C...A/0/*,
  [e5f6a7b8/48h/0h/0h/2h]xpub6D...B/0/*,
  [c9d0e1f2/48h/0h/0h/2h]xpub6E...C/0/*))#checksum
```

Plus a second, identical descriptor with `/1/*` instead of `/0/*` — those are the
change addresses. **You need both.**

> **No descriptor, but all three xpubs with origin?** Then you can assemble it yourself
> — exactly after the pattern above. The **order of the three keys does not
> matter**, because `sortedmulti` sorts them itself per BIP-67. The checksum after `#`
> Bitcoin Core computes for you with `getdescriptorinfo`.

> ### ⚠️ Neither descriptor nor the third xpub present?
> If you only have two seeds and know neither the descriptor nor the public key of the
> third, the wallet is **not recoverable**. There is no procedure to
> guess the missing xpub — that is cryptographically impossible, not merely hard.
> **That is why the descriptor is on every backup printout.**

---

## 2. The fastest path: Sparrow

For most people the right choice — graphical, free, open source, built for exactly this case.

### 2.1 Create wallet (watch-only only, no keys yet)

1. Download Sparrow from [sparrowwallet.com](https://sparrowwallet.com). **Verify the signature
   of the file** — the instructions are on the same page.
2. *File → New Wallet*, assign a name.
3. Policy Type: **Multi Signature**, Script Type: **Native SegWit (P2WSH)**, Quorum **2 of 3**.
4. Load descriptor: under the **Descriptor** tab open the text box, paste the
   descriptor and choose *Apply*.
5. Sparrow now shows three keys with their fingerprints. **Compare the three
   fingerprints with your printout.** If they do not match, you have the wrong descriptor.
6. Under *Settings → Server* choose a server — your own Electrum server or Bitcoin
   Core if available. Otherwise a public one; see the note below.
7. Right-click the wallet → *Rescan* from the birthday height. Your balance appears.

> **Privacy:** A public Electrum server sees your
> full wallet at this step — all addresses, all amounts, your IP. For a one-time rescue that
> is usually acceptable; for ongoing use it is not. If you have the choice, use your own
> server or Bitcoin Core.

### 2.2 Move everything into a new wallet

At this point **always sweep** — after a loss or
theft the old setup is considered possibly compromised.

1. Prepare a new destination wallet (fresh setup in this app, a hardware wallet, or a
   new Sparrow wallet) and obtain a receive address.
2. In the recovered wallet: *Send* tab, enter destination address, choose **Max**,
   set fee, *Create Transaction*.
3. *Finalize Transaction for Signing*. Sparrow now shows the unsigned transaction.
4. **Sign first key:** Sparrow asks for the seed. Enter word list. **One** of two
   required signatures appears.
5. **Sign second key:** same path with the second word list. Now there are
   two of two.
6. *Broadcast Transaction*.

**Done.** Your funds are in the new wallet.

> **Before you send, check the destination address character by character** — at least the first and
> last eight. That is the moment address poisoning strikes.

---

## 3. The path without a GUI: Bitcoin Core

Use this path if you have your own node, do not want to trust third-party software,
or Sparrow one day no longer exists.

> **Version:** **30.2 or newer.** Versions 30.0 and 30.1 had a bug that when
> migrating older wallets could delete wallet files; they were withdrawn by bitcoincore.org.
> Do not use them.

### 3.1 Create watch-only wallet

```bash
# Descriptor wallet without private keys
bitcoin-cli createwallet "rescue" true true "" false true true

# Compute checksums (even if you have them — typos show up here)
bitcoin-cli getdescriptorinfo "wsh(sortedmulti(2,[a1b2c3d4/48h/0h/0h/2h]xpubA/0/*,...))"
```

```bash
# Import both descriptors, receive and change.
# "timestamp" is a Unix timestamp (seconds since 1970), not a block height.
# From the birthday height e.g.:
#   bitcoin-cli getblockheader $(bitcoin-cli getblockhash 812345)
# and take the "time" field — here as example 1700000000 (Nov 2023).
# Alternatives: 0 (scan from genesis) or "now" (no historical scan).
bitcoin-cli -rpcwallet=rescue importdescriptors '[
  {"desc":"wsh(sortedmulti(2,...))#checksum1",
   "active":true,"internal":false,"range":[0,1000],"timestamp":1700000000},
  {"desc":"wsh(sortedmulti(2,...))#checksum2",
   "active":true,"internal":true, "range":[0,1000],"timestamp":1700000000}
]'
```

`importdescriptors` expects in the `timestamp` field a **Unix timestamp** (or `0` or
`"now"`). The birthday on the backup printout is instead a **block height**.
To get the timestamp from the height: `getblockhash <height>` and then
`getblockheader` or `getblockstats` — field `time`. When in doubt `0`: Core scans from genesis,
it takes longer but finds everything.

```bash
# Check: do the addresses match what you expect?
bitcoin-cli deriveaddresses "wsh(sortedmulti(2,...))#checksum1" "[0,5]"

# Additional rescan from block height (here the birthday height, not the timestamp)
bitcoin-cli -rpcwallet=rescue rescanblockchain 812345
bitcoin-cli -rpcwallet=rescue getbalances
```

### 3.2 Build transaction

```bash
bitcoin-cli -rpcwallet=rescue walletcreatefundedpsbt \
  '[]' '[{"bc1q...destination":0.0}]' 0 \
  '{"subtractFeeFromOutputs":[0],"fee_rate":15}'
```

Result is a PSBT in Base64. **Check it before you sign:**

```bash
bitcoin-cli decodepsbt "cHNidP8B..."
bitcoin-cli analyzepsbt "cHNidP8B..."
```

Verify: Does the amount go to the right address? Is the fee plausible? Are there
unexpected outputs?

### 3.3 Sign with both keys

Sign without permanently creating the private keys — each key in its own
throwaway wallet:

```bash
# First key
bitcoin-cli createwallet "signer1" false false "" false true true
bitcoin-cli -rpcwallet=signer1 importdescriptors '[{
  "desc":"wsh(sortedmulti(2,[fpA/48h/0h/0h/2h]XPRIV_A/0/*,[fpB/...]xpubB/0/*,[fpC/...]xpubC/0/*))#checksum",
  "active":false,"range":[0,1000],"timestamp":0}]'
bitcoin-cli -rpcwallet=signer1 walletprocesspsbt "cHNidP8B..."

# Second key, with the result from the previous step
bitcoin-cli createwallet "signer2" false false "" false true true
# ... same descriptor, but XPRIV_C instead of xpubC
bitcoin-cli -rpcwallet=signer2 walletprocesspsbt "<psbt-from-step-1>"
```

You get the `xprv` from your word list with a BIP-39/BIP-32 tool — Sparrow shows
it under *Tools → Wallet Import*, usable offline.

```bash
# Finalize and send
bitcoin-cli finalizepsbt "<psbt-with-two-signatures>"
bitcoin-cli testmempoolaccept '["<raw-transaction-hex>"]'   # check first!
bitcoin-cli sendrawtransaction "<raw-transaction-hex>"
```

```bash
# Clean up: remove the throwaway wallets with the private keys
bitcoin-cli unloadwallet "signer1" && bitcoin-cli unloadwallet "signer2"
# and then delete the wallet directories
```

---

## 4. Common cases

### Phone gone, backups of B and C present
The normal case. Path per Section 2 or 3, with word lists B and C. The phone is
not needed.

### Phone present, one backup lost
As long as the app runs, you have A and B on the device. Send everything into a fresh setup
**before** anything else happens — a second loss would then be final.

### New fingerprint registered, app reports key A as lost
Expected behaviour, not a bug: A is tied to the biometrics enrollment and is destroyed on change.
**B still lives** — it sits in an access class that the device passcode also
opens. So you have B on the device and C on paper, i.e. the quorum, and can migrate directly into
a fresh setup without needing B's word list.

### Passphrase forgotten
**No loss of funds.** The passphrase does not encrypt any key; it only authorizes
spending above the daily limit and changes to that limit. Below the limit you can
keep sending. Want to move everything: path per Section 2 or 3 with word lists B
and C.

### One key has fallen into other hands
One key alone can do nothing. But act promptly: create a **completely new** setup
with three fresh keys and move everything there, signed with the two keys
the attacker does not have. **Do not only replace the one key in the existing
descriptor** — otherwise the attacker only needs one more.

### Phone stolen, unlocked, passphrase unknown
The thief gets at most the daily limit (default: €200, with larger holdings up to
€500). **Move the rest immediately**: word lists B and C, path per Section 2, everything into a
fresh setup. You have the two keys they do not have.

---

## 5. Check this before you need it

The only backup plan that counts is the one you have tried. Recommendation: once after
setup and then once a year.

**Risk-free dry run:**

1. Import descriptor into Sparrow without keys (Section 2.1).
2. Check whether the first receive addresses match those in the app. If they do,
   your descriptor is correct and readable.
3. Send a small amount to one of those addresses.
4. Take it out again with B and C — without touching the phone.

If that works, your recovery works. If it does not, you find out at a
time when it only costs time.

---

## 6. Maxims

1. **The descriptor is as important as the keys.** The most common total loss with
   multisig is not the lost key, but the lost descriptor.
2. **Backup of B and backup of C never in the same place.** Two keys in one place are the
   quorum — a break-in would then be total loss, without any cryptography.
3. **The descriptor is not secret.** It contains only public keys. Store it freely
   multiple times, including digitally, including in a cloud.
4. **After every loss event, sweep, do not keep using.**
5. **Always check the destination address character by character** — at least first and last eight.
