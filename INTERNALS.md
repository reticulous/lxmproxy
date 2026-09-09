# lxmproxy — internals

```
LxmproxyService::onInit()          [boot task]  defaults, the acct.* sentinels,
 ↓                                              mint the identity, publish the
 ↓                                              address, register the CLI verb
rnsServiceRegister → lxmproxyStart [rnsd up]    spawn / un-park the server task
 ↓
lxmproxyTask                       [own task]   itsServerPortOpen(150), the
 ↓                                              resource aux (101), two storage
 ↓                                              subscriptions
s.lxmproxy.enabled?   no  → park on the 1 s poll; nothing is hosted
 ↓ yes
serverOpen(): rnsdDestOpen("lxmproxy.server") + rnsdDestListenChannels(150)
 ↓                                              + announce [label]
per accepted Channel                            one session_t
 ↓ read rnsd.chan.<tag>.remote_identity (rnsd validated it)
sessIdentify(): derive the account's dest, look up its slot, send HELLO
 ↓ every second, and on any write under s.lxmf.id.
pushScan(): walk this account's records → MSG for what is owed, STATUS for what
 ↓          moved, STATE for what only this box knows; apply the quota gate
hourly: retentionSweep()
```

Maintainer reference for the LXMF proxy **server**. The [README](README.md) is
the operator guide; the client half and the frame codec are in
[lxmf](../lxmf) (`lxmproxy_wire.h`, lxmf INTERNALS §8c). This document is
self-authoritative for what this straddle does.

---

## 1. Everything this straddle adds

Nothing upstream corresponds to it, so this is an inventory against the rest of
the workspace rather than against a baseline implementation.

1. **A hosted account is an ordinary lxmf identity.** `lxmfImportIdentity(key,
   name, "server", sync)` puts the handed-over key in a free lxmf slot; from
   that moment lxmf registers and announces it, receives into its own record
   store, and its delivery queue owns retry, backoff and `delivery_timeout`.
   This straddle writes drafts and reads statuses. There is no spool, no second
   store, and no re-implementation of anything lxmf already does.
2. **The `lxmproxy.server` destination**, on an identity of the box's own
   (`secrets.lxmproxy.identity`) — never one derived from an account. A
   destination hash is `H(name ‖ identity_hash)` and an account's identity hash
   is public in every `lxmf.delivery` announce, so an account-derived proxy
   address would be computable by anyone who has ever seen that account
   announce, and the announce would say out loud whose mail is here.
3. **One session per client Channel** (`rnsdDestListenChannels` →
   `LXMPROXY_CHAN_PORT` 150), keyed by the account it identified as.
4. **The bookkeeping either end of lxmf's store**: what is owed (`handed`),
   what it costs (`quota_kb`, `retain_days`), and who may be served
   (`s.lxmproxy.serves`).
5. **Two rns primitives this straddle is the first consumer of**:
   `rnsdChannelSendResource` (a frame past the channel MDU, on the Channel's
   hidden Link) and `rnsdDestSetAccept` (the per-destination inbound gate,
   reached through lxmf's `lxmf.id.<n>.accept` because only lxmf holds the
   handle).

### Not present

- **Several clients on one account.** That is read state, deletion propagation
  and per-client cursors — actual IMAP, and a different shape. Not an
  increment; do not half-build toward it. Everything flashes together, so
  deferring costs nothing.
- **An archive.** `keep_handed` exists so a box with room can keep messages, but
  nothing here searches them, and the client's copy stays the one that is
  browsed. Full-text search over a large archive is the same IMAP shape.
- **Ciphertext-only hosting.** The endgame, and a different design.
- **Consumer-side request handlers.** µR runs a request's response generator
  synchronously on the rnsd task, so only rnsd's own handlers exist. This does
  not need them.

---

## 2. The task

One FreeRTOS task, priority 1, core 0, 8 KB PSRAM stack, single wait point
`itsPoll(1 s)`. It parks rather than exits across `rns stop`/`rns start`, so its
ITS ports and client slots are reused.

Two storage subscriptions, both firing on this task:

| Subscription | Fires for | Effect |
|---|---|---|
| `s.lxmproxy.enabled` | the operator's switch | `s_enableDirty`; the loop reconciles |
| `s.lxmf.id.` | anything lxmf writes under an identity | `s_storeDirty`; every session scans on the next pass |

The second is deliberately coarse. A burst of leaf writes — one inbound message
is several — costs one scan rather than one per leaf, and the scan is bounded by
what this box still holds, which under the default delete-on-handover policy is
what nobody has collected yet.

Two ITS ports:

- **`LXMPROXY_CHAN_PORT` (150)** — where rnsd back-connects each accepted
  inbound Channel, with an `rnsd_link_incoming_t` naming the rnsd-generated tag.
- **`RNSD_LINK_RESOURCE_AUX_PORT` (101)** — the port every link consumer shares.
  rnsd delivers the Resource lifecycle here by task handle, so this straddle
  must open it or rnsd logs "aux send to unregistered port 101" and frees the
  buffer the frame was carrying.

## 3. The session state machine

```
onChanConnect      → session_t{ tag, opened_s }         nothing is trusted yet
 ↓ 1 Hz
sessIdentify()     rnsd.chan.<tag>.remote_identity present?
                     no, and > LXMPROXY_IDENT_WAIT_S (45 s) → close
                     yes → derive the delivery dest from the identity hash,
                           slot = lxmfSlotForDest(), serving = approved && slot
                     → HELLO [label, quota, envelope, retain, serving, reason]
 ↓
handleFrame()      acts on nothing before have_ident
```

**The identify is the credential.** rnsd validates the LINKIDENTIFY signature
before its result appears in `rnsd.chan.<tag>.remote_identity`, so reading that
key is reading a proven fact. `handleFrame` refuses every frame until it has
been read — an unidentified Channel can do nothing at all.

**The account's address follows from the identify alone.** RNS address
derivation only ever consumed the identity's hash, so
`rnsdDestinationHashFromIdentityHash(ident, "lxmf", "delivery", …)` is the whole
lookup. Nothing is asked of the client and nothing is guessed.

**A slot counts as served only when its `proxy_role` is `server`.** An account
whose owner also happens to run lxmf on this box would otherwise look
provisioned. That check is what keeps "an identity that lives here" and "an
identity hosted here for somebody else" apart.

**Newest Channel wins.** A client whose Channel died silently reconnects before
this end has gone stale, so two identified Channels for one account is an
ordinary state rather than an error. The one that has just identified is the
account's; `sessIdentify` closes the other, carrying over any identity handshake
in flight — that belongs to the account, not to the Channel it was asked on.
rnsd also evicts the longest-idle link when its table is full, so a quiet proxy
Channel on a busy box can be dropped through no fault of its own; the client
simply reconnects into this same path.

## 4. HANDOVER, and the order the ratchets go in

```
handleHandover:
  approved?                    no → SERVING [0, "not approved by the operator"]
  already hosted?              yes → SERVING [1]        (a repeat is a no-op)
  already importing?           yes → nothing; the first one is still landing
  write secrets.rnsd.ratchets.<dest>          ← BEFORE the destination opens
  lxmfImportIdentity(key, name, "server", sync=false)
  awaiting_import = true, id_deadline_s = now + 15 s
 ↓ 1 Hz, sessIdentityTick
  lxmfSlotForDest() answers?   yes → slot, serving, SERVING [1]
  past the deadline?           → un-write the ratchets, SERVING [0, reason]
```

**The ratchet record is written first, and that ordering is load-bearing.**
Peers encrypt opportunistic packets to the ratchet in the last announce they
heard, and only that ratchet's private key decrypts them. rnsd applies a
destination's retained set *when the destination opens*, so a record written
after the import would leave everything already in flight unreadable until each
peer heard this box's own announce.

**The import is asynchronous, and the wait is a state rather than a block.**
lxmf does the work on its own task; this end sets `awaiting_import` and the 1 Hz
pass watches `lxmfSlotForDest` for the answer. The synchronous form would park
this task for up to five seconds with every other session's mail behind it.

## 5. The push loop

`pushScan` runs when the session is dirty or every `LXMPROXY_SCAN_PERIOD_S`
(10 s). It walks the account's whole message subtree once
(`storageForEach` → `scanLeaf`, accumulating on the (peer, key) boundary — the
callback carries no ctx pointer, so the accumulator is file-scope, as lxmf's own
scans are) and does three things:

- **inbound with `handed == 0`, and not pushed in the last
  `LXMPROXY_REPUSH_S`** → `MSG`, with the body inline when it is within the
  inline threshold and `nil` when it is not. Its bytes count toward `owed`.
  `sent_msg_s` remembers when each was last offered, keyed `"<peer>/<key>"` —
  the inbound half of what `sent_status` does for outbound, and necessary for
  the same reason. `handed` is an acknowledgement, not a record of having sent:
  it cannot arrive until the client has stored the body, which is seconds away
  on a radio and never at all while the client is off the air. Scanning on that
  alone re-sent every unacknowledged message on every pass, so one arrival cost
  a push per scan — thirteen frames in half a second for a single message, into
  a Channel window five deep. The Channel already sequences and resends what
  goes unproved, so the interval is a backstop for a frame it gave up on rather
  than the delivery mechanism, which is why it is far longer than the scan
  period. The ledger is pruned to the rows each scan actually saw.
- **outbound whose status has moved, and which the client has not acknowledged**
  → `STATUS`, carrying `message_id` so the client can map its local key onto
  this box's record. `sent_status` remembers what was last relayed, keyed
  `"<peer>/<key>"`, and `SETTLED` is what clears the entry. The `handed` skip is
  the other half of that and is load-bearing, not tidiness: `SETTLED` clears the
  `sent_status` entry but only *asks* lxmf to delete the record, which happens
  on lxmf's task, so without the skip the next scan finds an unremembered
  terminal record and relays its status again — drawing another `SETTLED`,
  another delete, and one "deleted msg" line per scan until the record finally
  goes. Both acks are idempotent for the same reason: a `HANDED`/`SETTLED` for a
  record already marked `handed` is a repeat of the frame, not a second
  handover, and re-issues nothing.
- **the account's own state** → `STATE`, with the real announce time and how
  full the store is, so the client displays truth rather than intent.

**What is left is what is owed.** There is no cursor and no resume position,
because there is nothing to resume: a reconnect re-pushes the remainder and the
client dedups on `message_id`. A client record held with the body still absent
is a pending fetch, not a duplicate. A new Channel is a fresh `session_t`, so
`sent_msg_s` starts empty and that re-push is immediate — the ledger paces a
live session, and never delays a reconnect.

**`handed` is set by `HANDED`, and by nothing else.** rnsd proves a packet the
moment the hand-off to the consumer task succeeds, before anything is parsed or
stored, and a Resource's conclusion is likewise pre-persist. Neither is a
handover ack. The client sends `HANDED` once the record is in ITS storage with
its body, which is why a withheld body is never deleted before someone fetches
it.

**Deletion is a policy.** `keep_handed` decides whether `HANDED` also deletes
the record (via lxmf's `cmd.delete`, since lxmf owns the store). Today's policy
on an ESP32 is delete; a box that keeps everything is a config change rather
than a protocol revision.

### The inline threshold

`lxmproxyInlineThreshold(rtt_ms, override)` (lxmf's `lxmproxy_wire.cpp`), fed
from `rnsd.chan.<tag>.rtt_ms` — continuously re-measured on a held link — and
`s.lxmproxy.inline_bytes` as the override. It scales inversely with the round
trip from 8 KB at 250 ms, clamped to [256 B, 16 KB]. The clamp is what stops a
first-measurement outlier from either withholding everything or pushing a body
over a radio for minutes.

### Quota

`owed` is inbound not yet handed over **plus** outbound not yet settled — both
occupy the same store, and counting only one side would let a client fill the
box from the other. `handleSend` refuses a `SEND` that would overrun it with
`PROXY_REFUSED`, so the message stays on the device its owner can see rather
than becoming a record this box cannot keep.

`applyQuota` writes `lxmf.id.<slot>.accept`. lxmf
mirrors that onto `rnsdDestSetAccept`, and rnsd then drops that destination's
inbound — packets and Resource advertisements alike — **without proving them**.
The sender's receipt stays open and their own retry loop keeps the message,
which is the only "mailbox full" LXMF has. The key is ephemeral: a fresh boot
accepts, and whoever wants it shut re-asserts.

## 6. SEND

The client's local key is the idempotency key. `handleSend` returns early on a
record that already exists — a `SEND` repeated after a reconnect meets the same
record — and only clears `sent_status` so the next scan re-reports its status.

The draft is reproduced exactly as the client wrote it, **the client's own
timestamp included**, so the `message_id` both ends derive is the same one. Then
`lxmf.id.<slot>.cmd.send` hands it to lxmf's queue, which owns retry, backoff
and `delivery_timeout` from there. The `pn:` third segment carries a
propagation-node target through unchanged.

An oversize body is refused with `TOO_LARGE` on the spot rather than written and
failed, so the client sees the reason immediately.

## 7. RELEASE

```
handleRelease:
  held_ratchets = secrets.rnsd.ratchets.<dest>   ← before the destination goes
  slot = -1, serving = false
  lxmfDestroyIdentity(slot, sync=false)          ← DEREGISTER FIRST
  awaiting_release = true
 ↓ 1 Hz, sessIdentityTick
  secrets.lxmf.id.<slot>.privkey gone (or past the deadline)?
    → servesRemove(ident), RATCHETS [held_ratchets]
```

Deregistering before acknowledging is deliberate. The client stays proxied and
fully working until `RATCHETS` lands, so the window is one with **no**
registrant rather than two — and no registrant is the half that recovers on its
own, because the client's next announce settles it. Two registrants on one
address does not.

The destroy is asynchronous for the same reason the import is, and the
acknowledgement waits on the *evidence* that it landed — the private key being
gone — not on a timer.

## 8. The approved-account list

`s.lxmproxy.serves` is an array of per-field objects `{ id, label }`, `id` being
the account's identity hash and also the list's item id. This file is its only
writer: both UIs mutate it through the `lxmproxy.acct.{add,set,remove}`
sentinels, which land in `acctSentinel` on the storage task, validate there, and
answer on the shared `lxmproxy.acct.{error,done}` pair. So the 32-hex rule is
stated once, in firmware, and a rejection is a sentence the form shows rather
than a regex written twice.

Removal is also revocation: it destroys the identity slot, which takes the
account's address off the air here.

**Pending accounts are published as candidates** (`lxmproxy.pending.<i>.*`), so
the settings collection's `candidates:` block renders them and picking one opens
the approve form prefilled. That is what makes "nobody types a hash" true on
both surfaces. The array is trimmed each pass, so a client that goes away stops
being offered. `lxmproxy.pending_text` is the same fact as a finished line, on a
`when_key`-gated row: a device asking to be hosted is waiting on a person, and a
request nobody knows to look for is a request that never gets answered.

**Approval completes the handshake by itself.** A client refused for want of
approval is told `SERVING [ok=0, hold=1]` and holds its Channel open in
`PROVISIONING`. When the operator approves, the `serves_dirty` pass finds that
session and calls `sessHello` again; the client answers the fresh `HELLO` with
its `HANDOVER`. Without that re-offer the client gave up on the refusal and the
user had to ask to be proxied twice — once to make the request appear at all,
and again after approving it.

## 9. Frames over one Channel message

`LXMPROXY_MSG_MAX` is 300 B — conservative against the channel MDU (the link MDU
less the Channel envelope, less the two-byte msgtype prefix rnsd frames the ITS
pipe with). A larger frame goes as a Resource on the Channel's hidden Link via
`rnsdChannelSendResource`, and the bytes are identical either way, so
`lxmproxyParse` does not care which arrived.

Inbound Resources land on the shared aux port and are matched to a session
through `rnsd.chan.byid.<link_id>` → the tag. Outbound ones are acknowledged by
the protocol (`HANDED` / `SETTLED` / `STATUS`) and never by the transfer, so
their completion aux settles nothing; a failure is logged and the next scan
re-sends.

## 10. Pitfalls

- **Only lxmf may write an account's records.** Everything here goes through
  lxmf's own sentinels (`cmd.send`, `cmd.delete`, `cmd.announce`) or through
  fields lxmf does not own (`handed`). Writing a status or deleting a store file
  directly would race lxmf's delivery queue on its own data.
- **`nowS()` is monotonic; `wallS()` is the clock.** The retention sweep
  compares against a message's own timestamp, so it needs real time — and it
  refuses to run at all before the clock has been set, since on an unsynced
  device every message looks decades old.
- **`SERVING` waits for the slot, not for the call.** `lxmfImportIdentity`
  returns before the slot exists, so answering off its return value would tell a
  client it is proxied by something hosting nothing. `sessIdentityTick` answers
  off `lxmfSlotForDest`, which is the fact.
- **Nothing on this task may block on lxmf.** Both identity operations use the
  async form; the sync ones park this task for up to five seconds with every
  other session's mail behind them, and from the storage-task sentinel they
  would have the storage actor wait on itself.
- **A repeat HANDOVER is a no-op, not a re-import.** A client that missed the
  `SERVING` re-sends it; importing again would take a second identity slot for
  the same account and put two lxmf destinations on one address — inside this
  one box, where the invariant is easiest to break.
- **Stamp settings are device-wide.** See the README. The multi-account case
  logs and ignores rather than letting the last client to connect reprice
  everybody's mail.
- **The pending list is published from the session table, not from storage.**
  A client only appears there while its Channel is up, which is right: approving
  an account that is not currently asking to be hosted does nothing until it
  connects again, and the operator should be comparing the address on screen
  with the one on the device in front of them.
