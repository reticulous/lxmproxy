/**
 * lxmproxy — the always-on half of the LXMF proxy: a server that holds other
 * devices' LXMF accounts.
 *
 *   operator → s.lxmproxy.enabled = 1
 *     ↓
 *   mint secrets.lxmproxy.identity, host `lxmproxy.server`, announce the label
 *     ↓
 *   a client links + identifies with an ACCOUNT key   → pending, until approved
 *     ↓ operator approves (lxmproxy.cmd.approve)
 *   client HANDOVER [privkey, display_name, ratchets] → an ordinary lxmf
 *   identity on this device, registering and announcing the account's address
 *     ↓
 *   inbound mail lands in lxmf's own store → pushed over the Channel → HANDED
 *   → deleted here (a policy, not a wire rule)
 *
 * The account key is the credential. The link handshake proves this box holds
 * the proxy identity; the Channel's identify proves the client holds the
 * account key, which is the entitlement being checked. `s.lxmproxy.serves` is
 * operator policy about which accounts this box hosts — populated by approving
 * pending identifies — not an auth mechanism.
 *
 * A hosted account is an ORDINARY lxmf identity: lxmf's own store, delivery
 * queue, retry, delivery_timeout and status transitions do all the work, and
 * there is no separate spool. This straddle watches storage and translates.
 * Accounts per box are therefore bounded by lxmf's identity slots, and each
 * costs one hosted destination in rnsd.
 *
 * The cost is stated plainly and not designed around: both devices hold the
 * account key and the cleartext. The version where the server holds only
 * ciphertext is a propagation node, and it needs the world to change.
 *
 * The client half is in the lxmf straddle, because it touches everything lxmf
 * already owns; the shared frame codec is lxmf's `lxmproxy_wire.h`.
 */
#pragma once

#include "service.h"

/** Bring up lxmproxy: register the `lxmproxy` CLI verb and spawn the server
 *  task, which stays idle until `s.lxmproxy.enabled` flips on. Called from the
 *  generated straddle init dispatcher, after rns and lxmf. */
class LxmproxyService : public Service {
public:
    void onInit() override;
};
