# App concept

**Purpose:** the layer between the flows in SPECIFICATION.md §6 and the work packages
WP-60 … WP-68 — the inventory of screens, the states the app can be in, the five moments where
the interface carries a security property, and the rules for writing and drawing it.

**Standing:** this document adds no requirement to the specification and changes none. Where
the two disagree, the specification wins and this document is wrong (plan rule R3).

**Bearing documents:** [`SPECIFICATION.md`](SPECIFICATION.md) §6 (flows), §4.1 (threats) ·
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) WP-60 … WP-68

---

## 1. Where the interface carries a security property

Most of the app is an ordinary wallet and should be unremarkable. Five places are not. In each
of them the interface is the last line: if it fails, a property the architecture was built for
stops holding, without anything appearing to be broken. These five get the design budget.

| # | Moment | Carries | The actual failure mode |
|---|---|---|---|
| 1 | Proving the backup of B and C | T2 | Not refusal — the user photographs the screen and taps through |
| 2 | Naming two locations | T12 | A checkbox that means nothing |
| 3 | The confirmation before signing | T7 | A value that came from the app layer instead of the verifier |
| 4 | The first time the limit bites | T5a | Framed as an error rather than as the brake it is |
| 5 | Key A invalidated | T14 | Looks like a crash, is the intended property |

### 1.1 Proving the backup — blocking

Until it passes, `reveal_next_address` returns an error and the wallet has no receive address,
so no money can arrive in a setup that cannot be restored (§6.1). The challenge asks for word
**positions**, never shows words, is rendered natively with screenshots blocked, and returns
with **different** positions after a wrong answer so repetition cannot replace writing it down.

**Never:** an "I have written it down" checkbox, a skip link, a screenshot.

### 1.2 Naming two locations

The one rule the software can neither check nor enforce, and it carries the whole model: whoever
finds both papers needs no phone and no passphrase (T12). The person names the two places in
their own words as free text, stored locally. The names reappear on the backup printout and in
settings, and are re-confirmed periodically. Naming a place does more than any warning, because
it makes the abstraction concrete.

### 1.3 The confirmation before signing

Drawn natively from the `PsbtVerdict` the independent verifier read out of the transaction —
never from app-layer state (§6.2). The address appears in groups of four with the first and last
eight emphasised; amount and fee are separate lines; the fee carries its rate beside it so an
absurd fee is visible rather than buried in a number.

**Rule:** every value on this screen comes from the verifier's verdict.

### 1.4 The first time the limit bites

The specification deliberately does not ask about the limit during onboarding — with an empty
wallet nobody can answer sensibly what a daily ceiling should be, so the question is asked the
first time the limit actually stops something (§3.6.6). That is a teaching moment, not an error
state: explain, ask for the passphrase, proceed — and only then offer to adjust the limit.
Offering the adjustment as the way out of the dialog would make the limit self-defeating.

### 1.5 Key A invalidated

A new biometric enrolment destroys key A. That is the property that stops someone holding the
unlocked phone from enrolling their own face (T14), and to the user it looks exactly like a bug.
It is recognised on launch, named plainly, and answered with a path: B is still on the device
and C is off it, which is the quorum, so a move to a fresh setup is possible without B's paper
backup (S33). Never a red error screen, and never at the cost of the wallet configuration.

---

## 2. States the app can be in

Several rules in the specification are global states rather than screens. Modelling them once,
centrally, is what stops them being re-implemented differently on each screen.

**Setup, one way through:** Fresh install → choices (word length, source of C) → keys created →
**backup unproven** (blocking, no receive address) → locations named → **Active**.

**Exceptions, each with a named way out:**

| State | Entered when | Way out |
|---|---|---|
| Limit reached | spend above the 24 h allowance | passphrase (§3.6.3) |
| Reinstalled | first signature after a fresh install | passphrase, not switchable off (§3.6.5) |
| Key A invalidated | biometric enrolment changed | migrate with B + C (S33) |
| Drill due | passphrase unused for 60 days | one entry, deferrable, non-blocking (§3.6.8) |

**Separate modes, reachable without an existing wallet:** recovery (configuration plus two word
lists, watch-only then sweep out, §6.4), rotation after exposure (§6.5), and moving B to
hardware (§6.6). All three end in a fresh setup rather than a restored old one.

**Invariant across every state:** the wallet configuration is never discarded. Losing it is the
most common total loss in multisig (T11).

---

## 3. Screen inventory

Anything not on this list is not in version one.

| Package | Screens | The hard part |
|---|---|---|
| WP-61 | Explainer · word length · source of C · key A created · passphrase set · key B words · prove B · restart notice · key C words · prove C · name two locations · print the configuration · done | Thirteen screens before a satoshi can arrive; every one is a place to give up, and two must not be removable |
| WP-62 | Amount and recipient · fee choice · **native confirmation** · signing · sent | The confirmation is native and reads only from the verifier |
| WP-63 | Passphrase entry with word completion · drill · forgotten — what now | Under fifteen seconds on a slow phone (S25), never a plain text field |
| WP-64 | Address with QR · verify this address · gap-limit warning | One-tap independent re-derivation of the shown address (§6.3) |
| WP-65 | Enter configuration · scanning · balance found · enter word list · choose destination · swept | Works with no wallet on the device; ends in a fresh setup (S4) |
| WP-66 | Why rotate · new setup · sweep · waiting for confirmations · old setup retired | Never swap one key in place (§6.5) |
| WP-67 | Similar-address warning · dust marked in the list | Addresses from the history are not selectable as a destination at all (T8) |
| WP-68 | Limit · backend and privacy · locations · devices · about and honest limits | Loosening anything asks for the passphrase; the privacy note sits beside the choice, not in a help page |

Two screens carry the product's honesty and belong nowhere else: **about and honest limits**,
listing what the model does not cover in the same words as §4.2, and **forgotten — what now**,
which states plainly that a forgotten passphrase costs no money (§3.6.8).

---

## 4. Writing rules

This product must disclose what it does not protect against, and the disclosure is itself a
risk: whoever gives up mid-way stays where a single mistake costs everything (T20). Four rules
follow.

1. **Compare to where they came from, not to perfection.** "Not covered" alone is true and
   frightening; "not covered — and the same is true of the wallet you use today" is equally true
   and useful.
2. **Never a warning without a next step.** If there is nothing to do, say that plainly too.
3. **Say the amount, not the abstraction.** "200 € a day", not "20 % of the balance per rolling
   window". The precise form lives one tap deeper.
4. **No security theatre.** No shields, no lock icons, no green ticks for anything that was not
   actually checked. The app claims exactly what the verifier verified.

---

## 5. Visual direction

**Quiet until money moves.** Nearly the whole app is ink on a plain ground. Colour is reserved,
four of them, each with exactly one meaning, so a coloured element is information rather than
styling:

| Role | Used for |
|---|---|
| Action | the single primary button on a screen, and focus rings — nothing else |
| Attention | money is about to leave, or something needs care |
| Held | protected, confirmed, done |
| Not covered | the honest limits, and rejections — never for ordinary errors |

**Type.** A humanist sans carries the interface. Monospace is used for exactly three things:
amounts, addresses and word lists. That is a safety property rather than a style: an address has
to be readable character by character to defend against a look-alike (T8), and a word list has
to be transcribable without ambiguity. Digits align everywhere.

**Motion.** Almost none. One place earns it: a hold-to-sign control that fills over roughly
400 ms, making an irreversible act deliberate without adding a dialog. Reduced-motion turns even
that off.

**Deliberately not chosen:** a terminal aesthetic, and the familiar orange with glass and
gradients. Both signal "crypto" to people who are trying to leave crypto's failure modes behind.

---

## 6. What this does not settle

- **The app shell.** WP-06 recommends starting from an empty project; the decision is open.
  Nothing here depends on it — the screens and states are the same either way.
- **Crash reporting.** Decision O6 blocks WP-60. Until it is made, no diagnostics are wired in.
- **Whether a device the user already owns may serve as key C.** §2.7.9 accepts only a seed
  generated fresh on the device. That is a product decision, not a technical obstacle.
- **How any of this feels in the hand.** None of it has been in front of a person. Release
  criterion 15 requires a moderated test with at least ten participants; the drop-off points it
  finds are worth more than anything asserted here.
