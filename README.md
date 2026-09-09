# lxmproxy — hold other people's LXMF accounts, so their mail arrives while they are off

```
s.lxmproxy.enabled?   no  → nothing runs; the box's address is still published
 ↓ yes
mint secrets.lxmproxy.identity, host `lxmproxy.server`, announce the label
 ↓
a client links and identifies with an ACCOUNT key   → Waiting for approval
 ↓ the operator approves it
client HANDOVER [private key, display name, ratchets]
 ↓
the account becomes an ORDINARY lxmf identity here: it registers and announces
its own address, and receives and sends its own mail
 ↓ loop, while that client is connected
inbound → pushed over the Channel → the client stores it → HANDED → deleted here
outbound ← SEND ← the client;  its real status goes back verbatim
 ↓ the client releases it
RELEASE → deregister, hand the ratchets back → the account answers on its own
device again
```

**lxmproxy** is the always-on half of the LXMF proxy. One device — this one —
holds another device's LXMF account: it registers and announces the account's
`lxmf.delivery` destination, receives its mail and sends its outbound. The
account's owner keeps the same keys on their own, roaming device, registers
nothing, and exchanges messages with this one over a permanently-held Reticulum
Channel. The rest of the network sees an ordinary always-online LXMF node and
needs to implement nothing.

The cost is stated plainly and not designed around: **both devices hold the
account key and the cleartext.** The version where the server holds only
ciphertext is a propagation node, and it needs the world to change. This does
not.

## Origins

Store-and-forward that keeps the store blind to what it holds needs *other
people's clients* to speak its protocol. This is the pragmatic inverse, shaped
like POP and SMTP: one machine is the server, the other is the client, they
share an account, and nobody else has to know.

## What it does

- **Hosts accounts.** Each approved account is an ordinary
  [lxmf](../lxmf) identity on this device, so lxmf's own store, delivery queue,
  retry, `delivery_timeout` and status transitions do all the work. There is no
  separate spool and no second copy of anything. Accounts per box are bounded by
  lxmf's identity slots (four), and each costs one hosted destination in rnsd.
- **Pushes mail live** to whichever client is connected, and holds it for the
  ones that are not.
- **Sends on the account's behalf**, relaying the real `LxmfStatus` back so the
  owner sees the true outcome rather than a proxy-flavoured one.
- **Bounds what it costs**: a per-account store quota and a retention age, both
  the operator's to set.

The **client** half is not here — it is part of [lxmf](../lxmf), because it
touches everything lxmf already owns (the role setting, the delivery queue,
statuses and checkmarks, the message tree). So every node can be proxied without
carrying this straddle, and a small roaming board never pays for it. The shared
frame codec is lxmf's `lxmproxy_wire.h`.

## Turning it on

It is opt-in twice over: build it in, then switch it on.

```sh
spangap build reticulous/reticulous --with reticulous/lxmproxy --with <board>
```

Then Settings → Reticulum Mesh → LXMF proxy server → **Serve accounts**, or
`set s.lxmproxy.enabled=1`. Give it a **label** — that is what clients see when
they pick a server from the ones they have heard; nobody types an address.

The box announces `lxmproxy.server` with that label. A client
([lxmf](../lxmf), "Being proxied") picks it, links, and identifies with its
account key. It then shows up here as **Waiting for approval**:

```
lxmproxy pending           the clients that have identified but are not approved
lxmproxy approve <hash>    host that account
```

A waiting client holds its Channel open, so approving is the last thing anybody
has to do: this box re-offers immediately, the client hands the account over,
and it starts answering on that address. The person asking presses **Use a
proxy** once. The pane says how many devices are waiting on its own — that is a
row, not something behind a button — and the list below is where they are
answered.

Approving is the operator's decision about which accounts this box hosts;
**holding the account key is the entitlement**, and the approval list is policy
on top of it, not an authentication mechanism.

**Messaging an account you host.** From another identity on this same device it
works and never touches the radio: Reticulum keeps no path to its own
destinations, so the message is packed, signed and handed straight to the hosted
account's inbox here, then pushed on to its owner's device over their Channel.

## What the operator should know

**Exactly one device registers an account's address.** While this box serves an
account, the owner's device registers nothing and announces nothing. Removing
the account here takes its address off the air here; the owner's device puts it
back. There is a window where neither is on the air, because deregistering tells
the network nothing — the old announces keep bouncing around until they age out
and peers keep their cached path until it expires. The new registrant announces
at once and the network converges as that announce spreads.

**A message can be delivered here and still expire.** `retain_days` (default 7)
expires anything the owner never collected. That is what stops a client that
never comes back from pinning the store forever, and it is worth saying out loud
to whoever asked you to host their mail.

**At quota, mail is refused rather than dropped.** `quota_kb` (default 64) is
counted over everything this box is still holding for the account — inbound not
yet handed to the owner, and outbound not yet settled. A connected client drains
both. At the limit this box stops accepting that account's inbound *without
acknowledging it*, so the sender's own retry loop keeps the message on their
side; there is no LXMF way to tell an arbitrary sender "mailbox full" other than
withholding the proof. From the other direction the owner's own send is refused
outright (`PROXY_REFUSED`), so it stays on the device they can see rather than
becoming a record this box cannot keep.

**Every account on this box links to the same address.** The proxy destination
has its own identity, derived from no account — so the announce says nothing
about whose mail is here, and nobody who has seen an account announce can
compute this address. What it does concede is that an observer near the clients
can tell they share a server. Moving the server to new hardware means migrating
`secrets.lxmproxy.identity` or picking the new address on each client.

**Some settings are device-wide.** lxmf's `stamp_cost`, `enforce_stamps` and
propagation-node list belong to the device, not to an identity, so a box serving
more than one account cannot honour two answers. It keeps the one it has and
logs that it is ignoring the other, rather than letting the last client to
connect silently reprice everybody's mail or replace everybody's node list. A
box serving one account applies all of them. The display name and the
enabled switch are per identity and always apply.

## Storage variables

### Settings (`s.lxmproxy.*`)

| Key | Default | Meaning |
|---|---|---|
| `s.lxmproxy.enabled` | `0` | Serve accounts. Off, nothing is hosted and nothing is announced. |
| `s.lxmproxy.label` | `""` | The operator's label, announced. Empty falls back to the device name. |
| `s.lxmproxy.quota_kb` | `64` | Per account, over everything still held for it — inbound not yet handed to its owner plus outbound not yet settled. At the limit that account's inbound is refused unproved and its owner's sends are refused outright. |
| `s.lxmproxy.max_envelope_kb` | `32` | Largest single message accepted from a client to send. (The inbound side of this is rnsd's own `s.lxmf.max_resource_size`, which is device-wide.) |
| `s.lxmproxy.retain_days` | `7` | Unretrieved mail expires after this. `0` = never. |
| `s.lxmproxy.keep_handed` | `0` | Keep a message after its owner confirms it has stored it. Only sensible where the store is large. |
| `s.lxmproxy.inline_bytes` | `0` | Push bodies up to this size; larger ones are offered as a download. `0` derives it from each client's measured round trip. |
| `s.lxmproxy.serves.<i>.{id,label}` | — | The approved accounts. `id` is the account's 32-hex Reticulum identity hash; this straddle is the array's only writer. |

### Runtime (`lxmproxy.*`, RAM)

```
lxmproxy.up                    serving
lxmproxy.dest                  this box's lxmproxy.server address (published from boot)
lxmproxy.label                 the label as announced
lxmproxy.accounts              how many accounts are approved
lxmproxy.acct.<id>             per-account status pill, packed "text|color"
lxmproxy.pending.<i>.{id,name,dest}   identified clients awaiting approval
lxmproxy.pending_text          "N devices waiting for approval", empty when none
lxmproxy.acct.{add,set,remove} the settings collection's command keys
lxmproxy.acct.{error,done}     their answer pair
```

### Secrets

```
secrets.lxmproxy.identity      this box's proxy identity, 128-hex. Derived from no
                               account — see "Every account links to the same address".
```

## CLI — `lxmproxy`

```
lxmproxy                 state, address, accounts, live clients
lxmproxy accounts        the accounts this box has agreed to host
lxmproxy pending         identified clients awaiting approval
lxmproxy approve <hash>  host that account
lxmproxy revoke <hash>   stop hosting it (its address goes off the air here)
lxmproxy announce        put this box's address back on the air
```

## What it owns

```
lxmproxy/
└── esp-idf/
    ├── include/lxmproxy.h   the boot service
    └── src/lxmproxy.cpp     the server task: the hosted destination, one session
                             per client Channel, the push loop, quota, retention
```

The frames themselves are [lxmf](../lxmf)'s `esp-idf/include/lxmproxy_wire.h`.

## Dependencies

- [rns](../rns) — the Reticulum stack. The Channel API (`rnsdDestListenChannels`,
  `rnsdChannelSendResource`) and the per-destination accept gate
  (`rnsdDestSetAccept`) are what this is built on.
- [lxmf](../lxmf) — a hosted account IS an lxmf identity, so lxmf's store and
  delivery queue do the work; and the shared frame codec lives there.

## Read next

- [INTERNALS.md](INTERNALS.md) — the session state machine, the push loop, the
  ownership rules, and the pitfalls.
- [lxmf/README.md](../lxmf/README.md), "Being proxied" — the other end.
