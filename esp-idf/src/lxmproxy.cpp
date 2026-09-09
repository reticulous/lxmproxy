/* lxmproxy — the always-on half of the LXMF proxy. See lxmproxy.h for the
 * ladder and lxmf's lxmproxy_wire.h for the frames.
 *
 * One FreeRTOS task. It hosts the box's `lxmproxy.server` destination, accepts
 * an inbound Channel per client, and translates between that Channel and lxmf's
 * own storage — because a hosted account is an ordinary lxmf identity here, and
 * lxmf's store, delivery queue, retry and status transitions do all the work.
 * There is no separate spool and no second copy of anything.
 *
 * What this file owns is the bookkeeping either end of that:
 *
 *   - WHO may be served. The Channel's identify (validated by rnsd before its
 *     result appears in `rnsd.chan.<tag>.remote_identity`) proves the client
 *     holds the account key; `s.lxmproxy.serves` is the operator's policy about
 *     which of those accounts this box hosts. The server acts on no frame from
 *     a Channel whose identity it has not yet read.
 *   - WHAT IS OWED. One boolean per message, `handed`, separates owed from
 *     stored, so deletion is a POLICY and not a wire rule: today's policy on an
 *     ESP32 is delete on HANDED, and a box that keeps everything is a config
 *     change rather than a protocol revision. There is no cursor and no resume
 *     position to get wrong — what is left is what is owed, so a reconnect
 *     simply re-pushes the remainder.
 *   - WHAT IT COSTS. `retain_days` expires anything unretrieved (a client that
 *     never comes back cannot pin the store forever) and `quota_kb` bounds the
 *     bytes not yet handed over. At quota the account's destination stops
 *     accepting inbound WITHOUT proving it, so the sender's own retry loop
 *     keeps the message on their side — there is no other way to tell an
 *     arbitrary LXMF sender "mailbox full".
 */
#include "lxmproxy.h"
#include "lxmproxy_wire.h"
#include "lxmf.h"
#include "rnsd.h"
#include "ports.h"
#include "cli.h"
#include "its.h"
#include "log.h"
#include "spangap.h"
#include "storage.h"
#include "mem.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"

#include <sys/time.h>
#include <cctype>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

static const char* TAG = "lxmproxy";

#define LXMPROXY_VERSION        1
#define LXMPROXY_IDENTITY_KEY   "secrets.lxmproxy.identity"
/* One Channel per served account, and the accounts are bounded by lxmf's own
 * identity slots — a hosted account IS an lxmf identity. */
#define LXMPROXY_MAX_SESSIONS   4
/* A Channel whose initiator never identifies is not a client of ours. */
#define LXMPROXY_IDENT_WAIT_S   45
/* How often an idle session re-scans lxmf's store for work. Storage changes
 * mark the session dirty and it scans at once; this is the backstop. */
#define LXMPROXY_SCAN_PERIOD_S  10
/* How long a pushed MSG is left to be acknowledged before a scan offers it
 * again. `handed` is the only thing that retires an inbound record, and it
 * cannot arrive until the client has stored the body — seconds away on a radio,
 * and never at all while the client is off the air. Without this a scan re-sent
 * every unacknowledged message it could still see, so one arrival became a
 * push per scan for as long as the ack took. The Channel is already reliable
 * (it sequences and resends what goes unproved), so this is the backstop for a
 * frame the Channel itself gave up on, not the delivery mechanism — which is
 * why it is far longer than the scan period. A reconnect clears the ledger and
 * re-offers everything at once, which is what makes the remainder resumable
 * with no cursor. */
#define LXMPROXY_REPUSH_S       120
/* The retention sweep is cheap and its unit is days — an hour is plenty. */
#define LXMPROXY_SWEEP_PERIOD_S 3600
/* Resource opaque ids for our outbound frames. */
#define LXMPROXY_OPAQUE_BASE    0x40000u
/* A frame past this rides a Resource on the Channel's hidden Link. */
#define LXMPROXY_MSG_MAX        300

/* ─────────────── state ─────────────── */

struct session_t {
    bool        used = false;
    int         handle = -1;          /* inbound-Channel forward from rnsd */
    std::string tag;                  /* rnsd-generated "cin.<8hex>" */
    uint32_t    opened_s = 0;

    bool        have_ident = false;
    uint8_t     ident[RNSD_IDENT_HASH_LEN] = {};
    std::string ident_hex;
    uint8_t     dest[16] = {};        /* the account's lxmf.delivery destination */
    std::string dest_hex;

    int         slot = -1;            /* lxmf identity slot, -1 = not hosted here */
    bool        serving = false;
    bool        hello_sent = false;

    bool        dirty = true;         /* lxmf's store changed — scan */
    uint32_t    next_scan_s = 0;

    /* Identity work is asynchronous: lxmf does it on ITS own task and this one
     * never blocks waiting. `awaiting_*` is what the 1 Hz pass resolves, and
     * `id_deadline_s` is what stops a session waiting forever on a slot that is
     * never going to appear. `held_ratchets` is read BEFORE the destination
     * goes away and handed back once the deregistration has actually landed. */
    bool        awaiting_import = false;
    bool        awaiting_release = false;
    int         releasing_slot = -1;
    std::string held_ratchets;
    uint32_t    id_deadline_s = 0;

    /* The last outbound status relayed per message ("<peer>/<key>"), so a scan
     * emits STATUS only on a change. Bounded by the outbound this box still
     * holds, which SETTLED is what clears. */
    std::map<std::string, uint8_t> sent_status;
    /* When each inbound message was last pushed ("<peer>/<key>" → monotonic
     * seconds), so a scan offers one again only after LXMPROXY_REPUSH_S rather
     * than every time it walks a record the client has not acknowledged yet.
     * This is the inbound half of what sent_status does for outbound; `handed`
     * is an acknowledgement, not a record of having sent. Rebuilt from each
     * scan's own rows, so it holds only what this box is still carrying. */
    std::map<std::string, uint32_t> sent_msg_s;
    /* The last STATE relayed, so an idle scan puts nothing on the air. A
     * Channel message costs real airtime on a radio link, and "nothing has
     * changed" is not worth one. */
    std::string sent_state;
    /* What this box is holding for the account, as of the last scan: inbound
     * not yet handed over plus outbound not yet settled. It is what the quota
     * is measured against, and what refuses a SEND that would overrun it. */
    uint32_t    owed_bytes = 0;
};

static session_t   s_sessions[LXMPROXY_MAX_SESSIONS];
static TaskHandle_t s_task = nullptr;
static volatile bool s_stop = false;
static volatile bool s_parked = false;
static volatile bool s_enableDirty = false;
static volatile bool s_storeDirty = false;
static volatile bool s_servesDirty = false;   /* the approved list was edited */
static bool        s_wanted = false;
static int         s_destHandle = -1;
static uint32_t    s_opaque = LXMPROXY_OPAQUE_BASE;
static uint32_t    s_nextSweep_s = 0;

/* ─────────────── small helpers ─────────────── */

static std::string toHex(const uint8_t* p, size_t n)
{
    static const char* H = "0123456789abcdef";
    std::string s; s.resize(n * 2);
    for (size_t i = 0; i < n; ++i) { s[2*i] = H[p[i] >> 4]; s[2*i+1] = H[p[i] & 0xF]; }
    return s;
}

static bool fromHex(const std::string& s, uint8_t* out, size_t n)
{
    if (s.size() != n * 2) return false;
    for (size_t i = 0; i < n; ++i) {
        unsigned v = 0;
        if (std::sscanf(s.c_str() + 2*i, "%2x", &v) != 1) return false;
        out[i] = (uint8_t)v;
    }
    return true;
}

/* Monotonic since boot — deadlines and "how long ago", never a wire value. */
static uint32_t nowS(void) { return (uint32_t)(esp_timer_get_time() / 1000000); }

/* Real wall-clock seconds, for comparing against a message's own timestamp
 * (the retention sweep). Near-epoch on a device whose clock was never synced,
 * which is a missing time source rather than something this can paper over. */
static uint32_t wallS(void)
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (uint32_t)tv.tv_sec;
}

static std::string msgKey(int slot, const std::string& peer,
                          const std::string& key, const char* field)
{
    char b[160];
    std::snprintf(b, sizeof b, "s.lxmf.id.%d.msgs.%s.%s.%s",
                  slot, peer.c_str(), key.c_str(), field);
    return b;
}

static std::string quotaKb(void)   { return std::to_string(storageGetInt("s.lxmproxy.quota_kb", 64)); }
static uint32_t    quotaBytes(void){ return (uint32_t)storageGetInt("s.lxmproxy.quota_kb", 64) * 1024u; }
static uint32_t    envelopeMax(void){ return (uint32_t)storageGetInt("s.lxmproxy.max_envelope_kb", 32) * 1024u; }
static uint32_t    retainDays(void){ return (uint32_t)storageGetInt("s.lxmproxy.retain_days", 7); }
static bool        keepHanded(void){ return storageGetInt("s.lxmproxy.keep_handed", 0) != 0; }

static std::string serverLabel(void)
{
    std::string l = storageGetStr("s.lxmproxy.label", "");
    if (l.empty()) l = storageGetStr("sys.name", "");
    if (l.empty()) l = "LXMF proxy";
    return l;
}

/* ─────────────── the approved-account list ───────────────
 *
 * `s.lxmproxy.serves` is an array of per-field objects { id, label } — `id` is
 * the ACCOUNT's Reticulum identity hash, which is what the Channel identifies
 * with, and it is also the list's item id. It is operator policy, not an auth
 * mechanism: holding the account key is the entitlement, and this says which
 * key-holders this box has agreed to host.
 *
 * This file is the array's ONLY writer; both UIs mutate it through the
 * lxmproxy.acct.* sentinels, which land here. */

static int servesCount(void) { return storageArrayCount("s.lxmproxy.serves."); }

static std::string servesField(int idx, const char* field)
{
    char k[80];
    std::snprintf(k, sizeof k, "s.lxmproxy.serves.%d.%s", idx, field);
    return storageGetStr(k, "");
}

static int servesIndexOf(const std::string& id_hex)
{
    int n = servesCount();
    for (int i = 0; i < n; ++i) if (servesField(i, "id") == id_hex) return i;
    return -1;
}

static bool servesHas(const std::string& id_hex) { return servesIndexOf(id_hex) >= 0; }

static void servesWrite(int idx, const std::string& id, const std::string& label)
{
    char k[80];
    std::snprintf(k, sizeof k, "s.lxmproxy.serves.%d.id", idx);    storageSet(k, id.c_str());
    std::snprintf(k, sizeof k, "s.lxmproxy.serves.%d.label", idx); storageSet(k, label.c_str());
}

static bool servesAdd(const std::string& id_hex, const std::string& label)
{
    if (id_hex.size() != RNSD_IDENT_HASH_LEN * 2) return false;
    int idx = servesIndexOf(id_hex);
    storageBegin();
    servesWrite(idx >= 0 ? idx : servesCount(), id_hex, label);
    storageEnd();
    return true;
}

/* Drop an account, compacting the array so it stays contiguous. */
static void servesRemove(const std::string& id_hex)
{
    int idx = servesIndexOf(id_hex), n = servesCount();
    if (idx < 0) return;
    storageBegin();
    for (int i = idx; i < n - 1; ++i)
        servesWrite(i, servesField(i + 1, "id"), servesField(i + 1, "label"));
    char tail[80];
    std::snprintf(tail, sizeof tail, "s.lxmproxy.serves.%d", n - 1);
    storageUnset(tail);
    storageEnd();
}

/* ─────────────── frames out ─────────────── */

static bool sendFrame(session_t& s, const std::vector<uint8_t>& frame)
{
    if (s.handle < 0) return false;
    if (frame.size() > LXMPROXY_MSG_MAX) {
        void* buf = gp_alloc(frame.size());
        if (!buf) { warn("[%s] resource malloc %zuB failed", TAG, frame.size()); return false; }
        std::memcpy(buf, frame.data(), frame.size());
        /* rnsd owns buf from here and frees it once the engine has copied it. */
        return rnsdChannelSendResource(s.tag.c_str(), buf, frame.size(), s_opaque++);
    }
    std::vector<uint8_t> msg;
    msg.reserve(2 + frame.size());
    msg.push_back(0x01); msg.push_back(0x00);   /* RNS Channel MSGTYPE_RAW */
    msg.insert(msg.end(), frame.begin(), frame.end());
    if (itsSend(s.handle, msg.data(), msg.size(), pdMS_TO_TICKS(200)) == 0) {
        warn("[%s] %s: send dropped (%zuB)", TAG, s.tag.c_str(), frame.size());
        return false;
    }
    return true;
}

/* ─────────────── what lxmf's store holds for one account ─────────────── */

struct RecordRow {
    std::string peer, key;
    std::string dir, title, message_id;
    int  status = -1, tries = 0, handed = 0, body_absent = 0;
    int  ts = 0, body_size = 0;
};

/* storageForEach hands back leaves with no ctx pointer, so the walk accumulates
 * into file-scope state and flushes on the (peer, key) boundary — the same
 * shape lxmf's own scans use. */
static std::vector<RecordRow>* s_scanOut = nullptr;
static RecordRow               s_scanCur;
static size_t                  s_scanPfx = 0;

static void scanFlush(void)
{
    if (!s_scanCur.key.empty() && s_scanOut) s_scanOut->push_back(s_scanCur);
    s_scanCur = RecordRow{};
}

static void scanLeaf(const char* key, const char* val)
{
    if (!s_scanOut) return;
    /* key tail is "<peer>.<msgkey>.<field>" */
    const char* tail = key + s_scanPfx;
    const char* d1 = std::strchr(tail, '.');
    if (!d1) return;
    const char* d2 = std::strchr(d1 + 1, '.');
    if (!d2) return;
    std::string peer(tail, d1 - tail);
    std::string mk(d1 + 1, d2 - d1 - 1);
    std::string field(d2 + 1);
    if (peer != s_scanCur.peer || mk != s_scanCur.key) {
        scanFlush();
        s_scanCur.peer = peer;
        s_scanCur.key  = mk;
    }
    if      (field == "dir")         s_scanCur.dir = val ? val : "";
    else if (field == "status")      s_scanCur.status = val ? atoi(val) : -1;
    else if (field == "tries")       s_scanCur.tries = val ? atoi(val) : 0;
    else if (field == "handed")      s_scanCur.handed = val ? atoi(val) : 0;
    else if (field == "body_absent") s_scanCur.body_absent = val ? atoi(val) : 0;
    else if (field == "body_size")   s_scanCur.body_size = val ? atoi(val) : 0;
    else if (field == "ts")          s_scanCur.ts = val ? atoi(val) : 0;
    else if (field == "title")       s_scanCur.title = val ? val : "";
    else if (field == "message_id")  s_scanCur.message_id = val ? val : "";
}

static void scanAccount(int slot, std::vector<RecordRow>& out)
{
    char pfx[64];
    std::snprintf(pfx, sizeof pfx, "s.lxmf.id.%d.msgs.", slot);
    s_scanOut = &out;
    s_scanPfx = std::strlen(pfx);
    s_scanCur = RecordRow{};
    storageForEach(pfx, scanLeaf);
    scanFlush();
    s_scanOut = nullptr;
}

/* ─────────────── the push loop ───────────────
 *
 * What is left is what is owed. Every inbound record this box still holds
 * unhanded is pushed; every outbound whose status has moved since the last push
 * is relayed. There is no cursor: a reconnect re-pushes the remainder and the
 * client dedups on message_id — a record it holds with the body still absent is
 * not a duplicate, it is a pending fetch. */

/* The inline-body bound, from the link's own measured round trip. A body over
 * it is withheld: the client renders a download affordance and fetches it when
 * the user asks, rather than waiting behind a push it never asked for. */
static uint32_t inlineThreshold(const session_t& s)
{
    std::string k = "rnsd.chan." + s.tag + ".rtt_ms";
    uint32_t rtt = (uint32_t)storageGetInt(k.c_str(), 0);
    uint32_t ovr = (uint32_t)storageGetInt("s.lxmproxy.inline_bytes", 0);
    return lxmproxyInlineThreshold(rtt, ovr);
}

/* The account's inbound destination gate: shut once the bytes not yet handed
 * over reach the quota, opened again when the client has drained it. rnsd then
 * drops that destination's inbound WITHOUT proving, so the sender's own retry
 * loop keeps the message. */
static void applyQuota(const session_t& s, uint32_t owed_bytes)
{
    if (s.slot < 0) return;
    char k[48];
    std::snprintf(k, sizeof k, "lxmf.id.%d.accept", s.slot);
    bool full = quotaBytes() && owed_bytes >= quotaBytes();
    int want = full ? 0 : 1;
    if (storageGetInt(k, 1) != want) {
        storageSet(k, want);
        if (full)
            warn("[%s] %s: %u B owed reaches the %s kB quota — inbound gated",
                 TAG, s.dest_hex.c_str(), (unsigned)owed_bytes, quotaKb().c_str());
        else
            info("[%s] %s: below quota again — inbound accepted", TAG, s.dest_hex.c_str());
    }
}

static void pushScan(session_t& s)
{
    if (!s.serving || s.slot < 0) return;
    std::vector<RecordRow> rows;
    scanAccount(s.slot, rows);

    uint32_t owed = 0;
    uint32_t inline_max = inlineThreshold(s);
    uint32_t now_s = nowS();
    int pushed = 0;
    /* The push ledger, rebuilt from the rows this scan actually walked and
     * swapped in at the end. Carrying entries over one at a time would leave
     * behind whatever the scan no longer finds — handed over, expired, deleted
     * — so it is rebuilt rather than pruned. */
    std::map<std::string, uint32_t> still_held;

    for (const RecordRow& r : rows) {
        uint8_t mid[LXMPROXY_MID_LEN], peer[16];
        if (!fromHex(r.peer, peer, 16)) continue;

        if (r.dir == "in") {
            if (r.handed) continue;
            owed += (uint32_t)r.body_size;
            /* Inbound records are keyed by the real message_id. */
            if (!fromHex(r.key, mid, LXMPROXY_MID_LEN)) continue;
            std::string mk = r.peer + "/" + r.key;
            /* Offered recently enough that the client has not had time to
             * answer: the Channel is still carrying that frame, and sending it
             * again would only spend airtime racing its own resend. */
            auto sent = s.sent_msg_s.find(mk);
            if (sent != s.sent_msg_s.end() && now_s - sent->second < LXMPROXY_REPUSH_S) {
                still_held[mk] = sent->second;
                continue;
            }
            std::string content =
                storageGetStr(msgKey(s.slot, r.peer, r.key, "content").c_str(), "");
            bool inlineBody = content.size() <= inline_max;
            std::string name =
                storageGetStr(("s.lxmf.id." + std::to_string(s.slot) + ".contacts." +
                               r.peer + ".display_name").c_str(), "");
            if (sendFrame(s, lxmproxyBuildMsg(mid, peer, name.c_str(), (uint32_t)r.ts,
                                              r.title, (uint32_t)content.size(),
                                              inlineBody ? &content : nullptr))) {
                still_held[mk] = now_s;
                pushed++;
            }
            continue;
        }
        if (r.dir != "out") continue;
        /* Outbound this box still holds costs the same store. It counts toward
         * the quota so a client cannot fill the box from the other side. */
        owed += (uint32_t)r.body_size;

        /* Acknowledged: the client has this record's final status and said so.
         * Re-announcing it would draw another SETTLED, and every SETTLED
         * re-issues the delete — which lxmf performs on its own task, so the
         * record is still here on the next scan. That is a loop, and it shows
         * up as the same message being deleted several times. */
        if (r.handed) continue;

        /* Relay the account's real status the moment it moves. The
         * first STATUS carries the message_id, which is what maps the client's
         * local key onto this box's record. DRAFT is skipped: it is the state a
         * record is written in, a tick before lxmf's queue picks it up, and
         * relaying it would settle the client's copy on a status that means
         * "not sent yet". */
        if (r.status <= LXMF_ST_DRAFT) continue;
        std::string mk = r.peer + "/" + r.key;
        auto it = s.sent_status.find(mk);
        uint8_t st = (uint8_t)r.status;
        if (it != s.sent_status.end() && it->second == st) continue;
        uint8_t midbuf[LXMPROXY_MID_LEN];
        bool have_mid = fromHex(r.message_id, midbuf, LXMPROXY_MID_LEN);
        if (sendFrame(s, lxmproxyBuildStatus(r.key, peer, st, (uint32_t)r.ts,
                                             have_mid ? midbuf : nullptr)))
            s.sent_status[mk] = st;
    }

    s.sent_msg_s.swap(still_held);

    applyQuota(s, owed);
    s.owed_bytes = owed;

    /* What only this box knows, so the client displays truth rather than
     * intent: what is actually on the air, and how full its store is. Sent
     * only when it has moved — an idle scan puts nothing on the air. */
    char anns[24];
    std::snprintf(anns, sizeof anns, "%d",
                  storageGetInt(("lxmf.id." + std::to_string(s.slot) + ".last_announce_s").c_str(), 0));
    char q[48];
    std::snprintf(q, sizeof q, "%u kB of %s kB owed", (unsigned)(owed / 1024), quotaKb().c_str());
    std::string sig = std::string(anns) + '\x1f' + q + '\x1f' + s.dest_hex;
    if (sig != s.sent_state) {
        std::vector<std::pair<std::string, std::string>> st;
        st.emplace_back("announce_s", anns);
        st.emplace_back("quota", q);
        st.emplace_back("dest", s.dest_hex);
        if (sendFrame(s, lxmproxyBuildState(st))) s.sent_state = sig;
    }

    if (pushed) dbg("[%s] %s: pushed %d message(s)", TAG, s.dest_hex.c_str(), pushed);
}

/* ─────────────── frames in ─────────────── */

static void deleteRecord(int slot, const std::string& peer, const std::string& key)
{
    char v[128];
    std::snprintf(v, sizeof v, "%s/%s", peer.c_str(), key.c_str());
    char k[48];
    std::snprintf(k, sizeof k, "lxmf.id.%d.cmd.delete", slot);
    storageSet(k, v);
}

/* How long a session waits for lxmf to finish an identity import or destroy.
 * Both are queued to lxmf's own task, so this end never blocks on them. */
#define LXMPROXY_IDENTITY_WAIT_S 15

static void publishPending(void);   /* fwd — a refused handover republishes it */

static void handleHandover(session_t& s, const LxmproxyFrame& fr)
{
    if (!servesHas(s.ident_hex)) {
        /* `hold`: the client keeps the Channel and stays provisioning. The
         * operator is being waited on, not the protocol, and sessHello() below
         * re-offers the moment they approve — so the user asks to be proxied
         * once, not once before the approval and again after it. */
        sendFrame(s, lxmproxyBuildServing(false, "waiting for the operator to approve "
                                                 "this account", /*hold=*/true));
        publishPending();
        return;
    }
    if (s.slot >= 0) {          /* already hosted — a repeat is a no-op */
        s.serving = true;
        sendFrame(s, lxmproxyBuildServing(true, ""));
        return;
    }
    if (s.awaiting_import) return;   /* the first one is still landing */

    /* Ratchet state moves with the key, and ALL of it: peers encrypt to the
     * ratchet in the last announce they heard, and only that ratchet's private
     * decrypts them. Write the record BEFORE the destination opens — rnsd
     * applies a destination's retained set when it comes up, so a record
     * written after the import would leave everything already in flight
     * unreadable until each peer heard this box's own announce. */
    if (!fr.ratchets.empty())
        storageSet(("secrets.rnsd.ratchets." + s.dest_hex).c_str(), fr.ratchets.c_str());

    std::string priv = toHex(fr.privkey, 64);
    lxmfImportIdentity(priv.c_str(), fr.display_name.c_str(), "server",
                       /*sync=*/false);
    s.awaiting_import = true;
    s.id_deadline_s   = nowS() + LXMPROXY_IDENTITY_WAIT_S;
    info("[%s] taking %s over as \"%s\"", TAG,
         s.dest_hex.c_str(), fr.display_name.c_str());
}

/* The 1 Hz half of the two identity handshakes: lxmf does the work on its own
 * task, and this watches for the result rather than waiting on it. */
static void sessIdentityTick(session_t& s)
{
    uint32_t now_s = nowS();

    if (s.awaiting_import) {
        int slot = lxmfSlotForDest(s.dest);
        if (slot >= 0) {
            s.awaiting_import = false;
            s.slot    = slot;
            s.serving = true;
            s.dirty   = true;
            info("[%s] serving %s as identity slot %d", TAG, s.dest_hex.c_str(), slot);
            sendFrame(s, lxmproxyBuildServing(true, ""));
        } else if (now_s >= s.id_deadline_s) {
            s.awaiting_import = false;
            err("[%s] handover for %s failed (no free identity slot?)",
                TAG, s.dest_hex.c_str());
            storageUnset(("secrets.rnsd.ratchets." + s.dest_hex).c_str());
            /* A real refusal, not a wait: asking again changes nothing until
             * the operator frees a slot, so the client stops asking. */
            sendFrame(s, lxmproxyBuildServing(false, "no free identity slot on the server",
                                              /*hold=*/false));
        }
        return;
    }

    if (s.awaiting_release) {
        char k[48];
        std::snprintf(k, sizeof k, "secrets.lxmf.id.%d.privkey", s.releasing_slot);
        bool gone = !storageExists(k);
        if (gone || now_s >= s.id_deadline_s) {
            s.awaiting_release = false;
            if (!gone)
                warn("[%s] %s: the identity slot did not clear — releasing anyway",
                     TAG, s.dest_hex.c_str());
            servesRemove(s.ident_hex);
            info("[%s] released %s — the account registers on its own device again",
                 TAG, s.dest_hex.c_str());
            /* The ratchets go back only now, once this box has actually stopped
             * answering: the client stays proxied and working until it sees
             * them, so the window is one with NO registrant rather than two. */
            sendFrame(s, lxmproxyBuildRatchets(s.held_ratchets));
            s.held_ratchets.clear();
            s.releasing_slot = -1;
        }
    }
}

static void handleSend(session_t& s, const LxmproxyFrame& fr)
{
    if (!s.serving || s.slot < 0) return;
    std::string peer = toHex(fr.peer, 16);
    if (fr.content.size() > envelopeMax()) {
        sendFrame(s, lxmproxyBuildStatus(fr.key, fr.peer, LXMF_ST_TOO_LARGE,
                                         fr.ts, nullptr));
        return;
    }
    /* At quota this box has nowhere to put it. Refuse it here rather than
     * accept a record it cannot keep: the client shows PROXY_REFUSED and the
     * message stays on the device the operator can actually see. */
    if (quotaBytes() && s.owed_bytes + fr.content.size() > quotaBytes()) {
        warn("[%s] %s: SEND refused — %u B held reaches the %s kB quota", TAG,
             s.dest_hex.c_str(), (unsigned)s.owed_bytes, quotaKb().c_str());
        sendFrame(s, lxmproxyBuildStatus(fr.key, fr.peer, LXMF_ST_PROXY_REFUSED,
                                         fr.ts, nullptr));
        return;
    }
    /* The local key is the idempotency key: a SEND repeated after a reconnect
     * meets this same record and gets the same STATUS. A record already past
     * DRAFT is one we have; do not restart it. */
    if (storageExists(msgKey(s.slot, peer, fr.key, "status").c_str())) {
        s.sent_status.erase(peer + "/" + fr.key);   /* re-report on the next scan */
        return;
    }
    /* Reproduce the draft exactly as the client wrote it — the client's own
     * timestamp included, so the message_id both ends derive is the same one —
     * then hand it to lxmf's queue, which owns retry, backoff and the delivery
     * timeout from here. */
    storageBegin();
    storageSet(msgKey(s.slot, peer, fr.key, "dir").c_str(),     "out");
    storageSet(msgKey(s.slot, peer, fr.key, "peer").c_str(),    peer.c_str());
    storageSet(msgKey(s.slot, peer, fr.key, "title").c_str(),   fr.title.c_str());
    storageSet(msgKey(s.slot, peer, fr.key, "content").c_str(), fr.content.c_str());
    storageSet(msgKey(s.slot, peer, fr.key, "body_size").c_str(), (int)fr.content.size());
    storageSet(msgKey(s.slot, peer, fr.key, "ts").c_str(),      (int)fr.ts);
    storageSet(msgKey(s.slot, peer, fr.key, "status").c_str(),  0 /* DRAFT */);
    if (fr.have_reply_to)
        storageSet(msgKey(s.slot, peer, fr.key, "reply_to").c_str(),
                   toHex(fr.reply_to, LXMPROXY_MID_LEN).c_str());
    if (!fr.method.empty())
        storageSet(msgKey(s.slot, peer, fr.key, "method").c_str(), fr.method.c_str());
    char cmd[48], val[128];
    std::snprintf(cmd, sizeof cmd, "lxmf.id.%d.cmd.send", s.slot);
    if (fr.have_pn)
        std::snprintf(val, sizeof val, "%s/%s/pn:%s", peer.c_str(), fr.key.c_str(),
                      toHex(fr.pn, 16).c_str());
    else
        std::snprintf(val, sizeof val, "%s/%s", peer.c_str(), fr.key.c_str());
    storageSet(cmd, val);
    storageEnd();
    dbg("[%s] %s: SEND %s → %s", TAG, s.dest_hex.c_str(), fr.key.c_str(), peer.c_str());
}

static void handleConfig(session_t& s, const LxmproxyFrame& fr)
{
    if (s.slot < 0) return;
    bool announce = false;
    /* How many accounts THIS BOX HOSTS — not how many lxmf identities exist,
     * since the operator's own identity may well be one of them. */
    int accounts = 0;
    for (int n = 0; n < 4; ++n)
        if (storageGetStr(("s.lxmf.id." + std::to_string(n) + ".proxy_role").c_str(),
                          "off") == "server") accounts++;
    for (const auto& kv : fr.map) {
        if (kv.first == "display_name") {
            std::string cur = storageGetStr(("s.lxmf.id." + std::to_string(s.slot) +
                                             ".display_name").c_str(), "");
            if (cur != kv.second) {
                storageSet(("s.lxmf.id." + std::to_string(s.slot) + ".display_name").c_str(),
                           kv.second.c_str());
                announce = true;    /* the name is what the announce carries */
            }
        } else if (kv.first == "enabled") {
            storageSet(("s.lxmf.id." + std::to_string(s.slot) + ".enabled").c_str(),
                       atoi(kv.second.c_str()));
        } else if (kv.first == "stamp_cost" || kv.first == "enforce_stamps" ||
                   kv.first == "pn") {
            /* lxmf's stamp knobs and its propagation-node list are DEVICE-wide,
             * not per identity, so a box serving more than one account cannot
             * honour two answers. It keeps the one it has and says so, rather
             * than letting the last client to connect silently reprice
             * everybody's mail or replace everybody's node list. */
            if (accounts > 1) {
                verb("[%s] %s: ignoring %s — this box serves %d accounts and that "
                     "setting is device-wide", TAG, s.dest_hex.c_str(),
                     kv.first.c_str(), accounts);
                continue;
            }
            if (kv.first != "pn") {
                storageSet(("s.lxmf." + kv.first).c_str(), atoi(kv.second.c_str()));
                continue;
            }
            /* `hash|name|check` per line, index-ordered; a slot beyond the list
             * is cleared so a node removed on the client goes here too. */
            int i = 0;
            size_t at = 0;
            storageBegin();
            while (at <= kv.second.size() && i < 8) {
                size_t nl = kv.second.find('\n', at);
                std::string line = kv.second.substr(at, nl == std::string::npos
                                                        ? std::string::npos : nl - at);
                if (line.empty()) { if (nl == std::string::npos) break; at = nl + 1; continue; }
                size_t b1 = line.find('|'), b2 = line.rfind('|');
                if (b1 != std::string::npos && b2 != b1) {
                    char k[40];
                    std::snprintf(k, sizeof k, "s.lxmf.pn.%d.hash", i);
                    storageSet(k, line.substr(0, b1).c_str());
                    std::snprintf(k, sizeof k, "s.lxmf.pn.%d.name", i);
                    storageSet(k, line.substr(b1 + 1, b2 - b1 - 1).c_str());
                    std::snprintf(k, sizeof k, "s.lxmf.pn.%d.check", i);
                    storageSet(k, atoi(line.c_str() + b2 + 1));
                    i++;
                }
                if (nl == std::string::npos) break;
                at = nl + 1;
            }
            for (; i < 8; ++i) {
                char k[40];
                std::snprintf(k, sizeof k, "s.lxmf.pn.%d.hash", i);
                storageSet(k, "");
            }
            storageEnd();
        }
    }
    if (announce) {
        char k[48];
        std::snprintf(k, sizeof k, "lxmf.id.%d.cmd.announce", s.slot);
        storageSet(k, "1");
    }
}

static void handleRelease(session_t& s)
{
    if (s.awaiting_release) return;
    if (s.slot < 0) {
        servesRemove(s.ident_hex);
        sendFrame(s, lxmproxyBuildRatchets(""));
        return;
    }
    /* The retained ratchet set goes back with the release: until the client's
     * fresh announce reaches each peer, what they send is encrypted to ratchets
     * only this record opens. Read it before the destination goes away. */
    s.held_ratchets = storageGetStr(("secrets.rnsd.ratchets." + s.dest_hex).c_str(), "");

    /* Deregister FIRST, and acknowledge only once it has landed. The client
     * stays proxied and fully working until RATCHETS arrives, so the brief
     * window is one with NO registrant rather than two — which is the half of
     * the invariant that recovers on its own, since the client's next announce
     * settles it. */
    s.releasing_slot   = s.slot;
    s.slot             = -1;
    s.serving          = false;
    s.awaiting_release = true;
    s.id_deadline_s    = nowS() + LXMPROXY_IDENTITY_WAIT_S;
    s.sent_status.clear();
    s.sent_msg_s.clear();
    lxmfDestroyIdentity(s.releasing_slot, /*sync=*/false);
}

static void handleFrame(session_t& s, const LxmproxyFrame& fr)
{
    /* The identify is what proves the client holds the account key, and rnsd
     * validates it before its result appears. Act on nothing until it is read. */
    if (!s.have_ident) {
        verb("[%s] %s: frame %s before the identify — ignored", TAG,
             s.tag.c_str(), lxmproxyFrameName(fr.type));
        return;
    }
    dbg("[%s] %s: %s", TAG, s.dest_hex.c_str(), lxmproxyFrameName(fr.type));

    switch (fr.type) {
    case LXMPROXY_FR_HANDOVER: handleHandover(s, fr); s.dirty = true; break;
    case LXMPROXY_FR_SEND:     handleSend(s, fr);     s.dirty = true; break;
    case LXMPROXY_FR_CONFIG:   handleConfig(s, fr);                   break;
    case LXMPROXY_FR_RELEASE:  handleRelease(s);                      break;

    case LXMPROXY_FR_FETCH: {
        if (!s.serving || s.slot < 0) break;
        std::string peer = toHex(fr.peer, 16);
        std::string mid  = toHex(fr.msg_id, LXMPROXY_MID_LEN);
        std::string content = storageGetStr(msgKey(s.slot, peer, mid, "content").c_str(), "");
        std::string rt      = storageGetStr(msgKey(s.slot, peer, mid, "reply_to").c_str(), "");
        uint8_t rtb[LXMPROXY_MID_LEN];
        bool have_rt = fromHex(rt, rtb, LXMPROXY_MID_LEN);
        sendFrame(s, lxmproxyBuildBody(fr.msg_id, fr.peer, content,
                                       have_rt ? rtb : nullptr));
        break;
    }
    case LXMPROXY_FR_HANDED: {
        if (s.slot < 0) break;
        std::string peer = toHex(fr.peer, 16);
        std::string mid  = toHex(fr.msg_id, LXMPROXY_MID_LEN);
        if (!storageExists(msgKey(s.slot, peer, mid, "status").c_str())) break;
        /* Already acknowledged — a repeat of the frame, not a second handover.
         * Deletion is asynchronous, so the record outlives the first ack and a
         * repeat would ask for its removal all over again. */
        if (storageGetInt(msgKey(s.slot, peer, mid, "handed").c_str(), 0)) break;
        /* One boolean separates owed from stored, which is what makes deletion
         * a policy: an ESP32 deletes, a box with room keeps. */
        storageSet(msgKey(s.slot, peer, mid, "handed").c_str(), 1);
        if (!keepHanded()) deleteRecord(s.slot, peer, mid);
        s.dirty = true;
        break;
    }
    case LXMPROXY_FR_SETTLED: {
        if (s.slot < 0) break;
        std::string peer = toHex(fr.peer, 16);
        if (!storageExists(msgKey(s.slot, peer, fr.key, "status").c_str())) break;
        if (storageGetInt(msgKey(s.slot, peer, fr.key, "handed").c_str(), 0)) break;
        storageSet(msgKey(s.slot, peer, fr.key, "handed").c_str(), 1);
        if (!keepHanded()) deleteRecord(s.slot, peer, fr.key);
        s.sent_status.erase(peer + "/" + fr.key);
        s.dirty = true;
        break;
    }
    default:
        verb("[%s] %s: unexpected frame %u", TAG, s.tag.c_str(), fr.type);
        break;
    }
}

/* ─────────────── pending accounts (what the operator approves) ─────────────── */

/* The clients that have identified but whose accounts the operator has not
 * approved. Published as an ephemeral array so the settings list can render
 * them as candidates: picking one opens the approve form prefilled, which is
 * how nobody ever types a hash. */
static void publishPending(void)
{
    int i = 0;
    storageBegin();
    for (auto& s : s_sessions) {
        if (!s.used || !s.have_ident || s.serving) continue;
        if (servesHas(s.ident_hex)) continue;
        char k[64];
        std::snprintf(k, sizeof k, "lxmproxy.pending.%d.id", i);
        storageSet(k, s.ident_hex.c_str());
        /* An account that has never announced has no name to show, so its
         * address is what identifies it — which is what the operator compares
         * against the one on the device in front of them. */
        std::string nm = storageGetStr(("lxmf.announces." + s.dest_hex + ".name").c_str(), "");
        std::snprintf(k, sizeof k, "lxmproxy.pending.%d.name", i);
        storageSet(k, nm.empty() ? s.dest_hex.c_str() : nm.c_str());
        std::snprintf(k, sizeof k, "lxmproxy.pending.%d.dest", i);
        storageSet(k, s.dest_hex.c_str());
        i++;
    }
    storageEnd();
    /* Trim what a previous pass left behind, so a client that goes away stops
     * being offered. The count is taken once — the deletes below move it. */
    int had = storageArrayCount("lxmproxy.pending.");
    for (int k = i; k < had; ++k) {
        char t[48];
        std::snprintf(t, sizeof t, "lxmproxy.pending.%d", k);
        storageDeleteTree(t);
    }
    /* Say so on the pane itself. A device asking to be hosted is waiting on a
     * person, and a request nobody knows to look for is a request that is never
     * answered — so this is a row that appears on its own, not something behind
     * a button the operator has to think to press. */
    char line[64];
    if (i == 0) line[0] = '\0';
    else std::snprintf(line, sizeof line, "%d device%s waiting for approval",
                       i, i == 1 ? "" : "s");
    if (storageGetStr("lxmproxy.pending_text", "") != line)
        storageSet("lxmproxy.pending_text", line);
}

/* Per-account status pills for the settings list, keyed by the identity hash
 * the list rows are identified by. Packed "text|color", both halves finished
 * here — no UI composes one. */
static void publishAccounts(void)
{
    int n = servesCount();
    for (int i = 0; i < n; ++i) {
        std::string id = servesField(i, "id");
        if (id.empty()) continue;
        const session_t* live = nullptr;
        for (const auto& s : s_sessions)
            if (s.used && s.have_ident && s.ident_hex == id) { live = &s; break; }
        const char* pill = live ? (live->serving ? "connected|green" : "linking|amber")
                                : "offline|grey";
        std::string k = "lxmproxy.acct." + id;
        if (storageGetStr(k.c_str(), "") != pill) storageSet(k.c_str(), pill);
    }
    if (storageGetInt("lxmproxy.accounts", -1) != n) storageSet("lxmproxy.accounts", n);
}

/* ─────────────── sessions ─────────────── */

static void sessHello(session_t& s);   /* fwd — sessIdentify and the approval both use it */

static session_t* sessByHandle(int handle)
{
    for (auto& s : s_sessions) if (s.used && s.handle == handle) return &s;
    return nullptr;
}

static void sessClose(session_t& s)
{
    if (s.handle >= 0) itsDisconnect(s.handle);
    s = session_t{};
}

static int onChanConnect(int handle, const void* data, size_t len)
{
    if (len < sizeof(rnsd_link_incoming_t)) return -1;
    const rnsd_link_incoming_t* in = (const rnsd_link_incoming_t*)data;
    session_t* slot = nullptr;
    for (auto& s : s_sessions) if (!s.used) { slot = &s; break; }
    if (!slot) { warn("[%s] no free session slot", TAG); return -1; }
    *slot = session_t{};
    slot->used     = true;
    slot->handle   = handle;
    slot->tag      = in->tag;
    slot->opened_s = nowS();
    info("[%s] client Channel %s", TAG, slot->tag.c_str());
    return (int)(slot - s_sessions);
}

static void onChanRecv(int handle, size_t /*avail*/)
{
    session_t* s = sessByHandle(handle);
    if (!s) return;
    PSRAM_BSS static uint8_t buf[1024];
    size_t got = itsRecv(handle, buf, sizeof buf, 0);
    if (got <= 2) return;      /* [msgtype:2 BE][payload] */
    LxmproxyFrame fr;
    if (!lxmproxyParse(buf + 2, got - 2, fr)) {
        warn("[%s] %s: malformed frame (%zuB)", TAG, s->tag.c_str(), got - 2);
        return;
    }
    handleFrame(*s, fr);
}

static void onChanDisc(int ref)
{
    if (ref < 0 || ref >= LXMPROXY_MAX_SESSIONS) return;
    session_t& s = s_sessions[ref];
    if (!s.used) return;
    info("[%s] client Channel closed (%s)", TAG, s.tag.c_str());
    s.handle = -1;
    sessClose(s);
}

/* A frame too big for one Channel message arrives as a Resource on the
 * Channel's hidden Link; `rnsd.chan.byid.<link_id>` names the channel it
 * belongs to. */
static void onResourceAux(TaskHandle_t /*sender*/, const void* data, size_t len)
{
    if (len < sizeof(rnsd_link_resource_done_t)) return;
    rnsd_link_resource_done_t d;
    std::memcpy(&d, data, sizeof d);
    if (d.opcode != RNSD_LINK_RESOURCE_INBOUND_DONE) {
        if (d.opcode == RNSD_LINK_RESOURCE_FAILED)
            warn("[%s] outbound resource failed (opaque=%u)", TAG, (unsigned)d.opaque_id);
        return;
    }
    std::string tag = storageGetStr(
        ("rnsd.chan.byid." + toHex(d.link_id, 16)).c_str(), "");
    for (auto& s : s_sessions) {
        if (!s.used || s.tag != tag) continue;
        LxmproxyFrame fr;
        if (d.buf && d.len && lxmproxyParse((const uint8_t*)d.buf, d.len, fr))
            handleFrame(s, fr);
        else
            warn("[%s] %s: malformed resource frame", TAG, s.tag.c_str());
        break;
    }
    if (d.buf) rnsdResourceRelease(d.buf);
}

/* Read the initiator's identity once rnsd has validated it, work out which
 * account it is, and open the conversation with HELLO. */
static void sessIdentify(session_t& s)
{
    std::string ih = storageGetStr(("rnsd.chan." + s.tag + ".remote_identity").c_str(), "");
    if (ih.size() != RNSD_IDENT_HASH_LEN * 2) {
        if (nowS() - s.opened_s > LXMPROXY_IDENT_WAIT_S) {
            info("[%s] %s: no identify — closing", TAG, s.tag.c_str());
            sessClose(s);
        }
        return;
    }
    if (!fromHex(ih, s.ident, RNSD_IDENT_HASH_LEN)) return;
    s.ident_hex  = ih;
    s.have_ident = true;
    /* The address derivation only ever consumed the identity's hash, so the
     * account's delivery destination follows from the identify alone. */
    if (!rnsdDestinationHashFromIdentityHash(s.ident, "lxmf", "delivery", s.dest)) {
        warn("[%s] %s: cannot derive a delivery address for %s", TAG,
             s.tag.c_str(), ih.c_str());
        sessClose(s);
        return;
    }
    s.dest_hex = toHex(s.dest, 16);

    /* Newest Channel wins. A client whose Channel died silently reconnects
     * before this end has gone stale, so two identified Channels for one
     * account is an ordinary state rather than an error — and the one that just
     * identified is the account's. Close the other; the client is not on it. */
    for (auto& o : s_sessions) {
        if (&o == &s || !o.used || !o.have_ident || o.ident_hex != s.ident_hex) continue;
        info("[%s] %s reconnected — closing the older Channel (%s)", TAG,
             s.dest_hex.c_str(), o.tag.c_str());
        /* An identity handshake in flight on the old session belongs to this
         * account, not to that Channel: carry it over rather than restart it. */
        if (o.awaiting_import || o.awaiting_release) {
            s.awaiting_import  = o.awaiting_import;
            s.awaiting_release = o.awaiting_release;
            s.releasing_slot   = o.releasing_slot;
            s.held_ratchets    = o.held_ratchets;
            s.id_deadline_s    = o.id_deadline_s;
        }
        sessClose(o);
    }

    s.slot = lxmfSlotForDest(s.dest);
    /* Only a slot this box actually hosts counts as served: an account whose
     * owner also runs lxmf here would otherwise look provisioned. */
    if (s.slot >= 0) {
        std::string role = storageGetStr(("s.lxmf.id." + std::to_string(s.slot) +
                                          ".proxy_role").c_str(), "off");
        if (role != "server") s.slot = -1;
    }
    sessHello(s);
}

/* The conversation-opener, and also the "you may proceed now" the operator's
 * approval sends: a client that is holding the Channel waiting to be approved
 * answers a fresh HELLO with its HANDOVER, so approving is the last thing
 * anybody has to do. */
static void sessHello(session_t& s)
{
    bool approved = servesHas(s.ident_hex);
    s.serving = approved && s.slot >= 0;

    const char* reason = s.serving ? ""
                       : approved  ? "approved — send the account over"
                                   : "waiting for the operator to approve this account";
    info("[%s] %s identified as %s (%s)", TAG, s.tag.c_str(), s.dest_hex.c_str(),
         s.serving ? "serving" : reason);
    sendFrame(s, lxmproxyBuildHello(serverLabel().c_str(),
                                    (uint32_t)storageGetInt("s.lxmproxy.quota_kb", 64),
                                    (uint32_t)storageGetInt("s.lxmproxy.max_envelope_kb", 32),
                                    retainDays(), s.serving, reason));
    s.hello_sent = true;
    s.dirty = true;
    publishPending();
}

/* ─────────────── retention ───────────────
 *
 * A client that never comes back cannot pin the store forever. The consequence
 * is stated in the UI rather than designed away: a message can be
 * proof-delivered to this box and still expire before its owner ever sees it. */
static void retentionSweep(void)
{
    uint32_t days = retainDays();
    if (!days) return;
    uint32_t now = wallS();
    if (now < days * 86400u) return;   /* clock never synced — nothing has aged */
    uint32_t cutoff = now - days * 86400u;
    for (int slot = 0; slot < 4; ++slot) {
        std::string role = storageGetStr(("s.lxmf.id." + std::to_string(slot) +
                                          ".proxy_role").c_str(), "off");
        if (role != "server") continue;
        std::vector<RecordRow> rows;
        scanAccount(slot, rows);
        int dropped = 0;
        for (const RecordRow& r : rows) {
            if (r.dir != "in" || r.handed) continue;
            if (r.ts == 0 || (uint32_t)r.ts >= cutoff) continue;
            deleteRecord(slot, r.peer, r.key);
            dropped++;
        }
        if (dropped)
            info("[%s] slot %d: %d unretrieved message(s) expired after %u days",
                 TAG, slot, dropped, (unsigned)days);
    }
}

/* ─────────────── the hosted destination ─────────────── */

static void onDestRecv(int, size_t) {}
static void onDestDisc(int) { s_destHandle = -1; }

static void publishDest(void)
{
    uint8_t dh[RNSD_DEST_HASH_LEN];
    if (!rnsdDestinationHash(LXMPROXY_IDENTITY_KEY, "lxmproxy", "server", dh)) return;
    storageSet("lxmproxy.dest", toHex(dh, RNSD_DEST_HASH_LEN).c_str());
}

static void serverAnnounce(void)
{
    if (s_destHandle < 0) return;
    std::vector<uint8_t> ad = lxmproxyBuildAnnounce(serverLabel().c_str());
    std::vector<uint8_t> f;
    f.reserve(1 + ad.size());
    f.push_back(RNSD_DEST_ANNOUNCE);
    f.insert(f.end(), ad.begin(), ad.end());
    itsSend(s_destHandle, f.data(), f.size(), pdMS_TO_TICKS(200));
}

static void serverOpen(void)
{
    /* One proxy destination per box, with its OWN identity — never one derived
     * from an account. A destination hash is H(name ‖ identity_hash) and an
     * account's identity hash is public in every lxmf.delivery announce, so an
     * account-derived proxy address would be computable by anyone who has ever
     * seen that account announce, and the announce would say out loud which
     * account this box serves. What an independent identity does concede is
     * that every account here links to the same hash; that is accepted. */
    rnsdIdentityGenerate(LXMPROXY_IDENTITY_KEY);   /* idempotent */
    s_destHandle = rnsdDestOpen("lxmproxy.server", LXMPROXY_IDENTITY_KEY, /*SINGLE*/0,
                                /*ref*/0, onDestRecv, onDestDisc);
    if (s_destHandle < 0) { warn("[%s] rnsdDestOpen failed (%d)", TAG, s_destHandle); return; }
    if (!rnsdDestListenChannels(s_destHandle, LXMPROXY_CHAN_PORT))
        warn("[%s] rnsdDestListenChannels failed", TAG);
    publishDest();
    storageBegin();
    storageSet("lxmproxy.up", 1);
    storageSet("lxmproxy.label", serverLabel().c_str());
    storageEnd();
    serverAnnounce();
    info("[%s] serving as \"%s\" on %s", TAG, serverLabel().c_str(),
         storageGetStr("lxmproxy.dest", "").c_str());
}

static void serverClose(void)
{
    for (auto& s : s_sessions) if (s.used) sessClose(s);
    if (s_destHandle >= 0) itsDisconnect(s_destHandle);
    s_destHandle = -1;
    storageBegin();
    storageSet("lxmproxy.up", 0);
    storageSet("lxmproxy.dest", "");
    storageEnd();
    info("[%s] stopped", TAG);
}

/* ─────────────── operator commands ─────────────── */

/* The settings collection and the CLI mutate the approved list only through
 * these, and the hash is validated behind them: a rejection is a sentence the
 * form shows, never a rule duplicated in two UIs. */
static void acctSentinel(const char* key, const char* val)
{
    if (!val || !*val) return;
    const char* tail = std::strrchr(key, '.');
    if (!tail) return;
    ++tail;
    std::string err_msg;

    if (!std::strcmp(tail, "add") || !std::strcmp(tail, "set")) {
        cJSON* o = cJSON_Parse(val);
        if (!o) err_msg = "Could not read the form.";
        else {
            cJSON* idj = cJSON_GetObjectItem(o, "id");
            cJSON* lbj = cJSON_GetObjectItem(o, "label");
            /* On `.set` the editor carries only the fields it offers, and the
             * item editor offers the label alone — the account identity is not
             * an operator's to retype. `_id` names the item being committed
             * against, so it is where the id comes from on an edit. */
            if (!cJSON_IsString(idj)) idj = cJSON_GetObjectItem(o, "_id");
            std::string id = cJSON_IsString(idj) ? idj->valuestring : "";
            std::string lb = cJSON_IsString(lbj) ? lbj->valuestring : "";
            if (id.size() != RNSD_IDENT_HASH_LEN * 2)
                err_msg = "An account identity is 32 hexadecimal characters.";
            else if (id.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
                err_msg = "An account identity is 32 hexadecimal characters.";
            else {
                for (auto& c : id) c = (char)tolower((unsigned char)c);
                servesAdd(id, lb);       /* .set edits the label in place */
                s_servesDirty = true;
                info("[%s] approved account %s (\"%s\")", TAG, id.c_str(), lb.c_str());
            }
            cJSON_Delete(o);
        }
    } else if (!std::strcmp(tail, "remove")) {
        /* This handler runs on the STORAGE task, so it drops the account from
         * the list and nothing more. Actually stopping — destroying the identity
         * slot, taking the address off the air — happens on the server task,
         * which notices a serving session whose account is no longer approved.
         * Doing it here would have the storage actor wait on itself. */
        servesRemove(val);
        s_servesDirty = true;
        info("[%s] no longer serving %s", TAG, val);
    } else {
        return;      /* .order — the list is not ordered */
    }

    storageSet("lxmproxy.acct.error", err_msg.c_str());
    if (err_msg.empty()) {
        static int s_ack = 0;
        storageSet("lxmproxy.acct.done", ++s_ack);
    }
    storageUnset(key);
    publishAccounts();
    publishPending();
}

static void cliLxmproxy(const char* args)
{
    std::string a = args ? args : "";
    while (!a.empty() && a.front() == ' ') a.erase(a.begin());

    if (a.empty() || a == "-h" || a == "help") {
        if (a.empty()) {
            cliPrintf("enabled   %s\n", storageGetInt("s.lxmproxy.enabled", 0) ? "yes" : "no");
            cliPrintf("label     %s\n", serverLabel().c_str());
            cliPrintf("address   %s\n", storageGetStr("lxmproxy.dest", "(not up)").c_str());
            cliPrintf("accounts  %d approved, quota %s kB each, retain %u days\n",
                      storageGetInt("lxmproxy.accounts", 0), quotaKb().c_str(),
                      (unsigned)retainDays());
            for (const auto& s : s_sessions) {
                if (!s.used) continue;
                cliPrintf("  %s  %s\n", s.have_ident ? s.dest_hex.c_str() : "(identifying)",
                          s.serving ? "serving" : "pending approval");
            }
            return;
        }
        cliPrintf("lxmproxy                 state, address, accounts, live clients\n");
        cliPrintf("lxmproxy accounts        the accounts this box has agreed to host\n");
        cliPrintf("lxmproxy pending         identified clients awaiting approval\n");
        cliPrintf("lxmproxy approve <hash>  host that account\n");
        cliPrintf("lxmproxy revoke <hash>   stop hosting it (its address goes with it)\n");
        cliPrintf("lxmproxy announce        put this box's address back on the air\n");
        return;
    }
    if (a == "accounts") {
        int n = servesCount();
        if (!n) { cliPrintf("no accounts approved\n"); return; }
        for (int i = 0; i < n; ++i)
            cliPrintf("%s  %s\n", servesField(i, "id").c_str(),
                      servesField(i, "label").c_str());
        return;
    }
    if (a == "pending") {
        bool any = false;
        for (const auto& s : s_sessions) {
            if (!s.used || !s.have_ident || s.serving || servesHas(s.ident_hex)) continue;
            cliPrintf("%s  address %s\n", s.ident_hex.c_str(), s.dest_hex.c_str());
            any = true;
        }
        if (!any) cliPrintf("nothing waiting\n");
        return;
    }
    if (a.rfind("approve ", 0) == 0) {
        std::string id = a.substr(8);
        while (!id.empty() && id.front() == ' ') id.erase(id.begin());
        if (id.size() != RNSD_IDENT_HASH_LEN * 2) {
            cliPrintf("usage: lxmproxy approve <32-hex account identity>\n");
            return;
        }
        servesAdd(id, "");
        publishAccounts();
        cliPrintf("approved %s — it will hand the account over on its next connect\n",
                  id.c_str());
        return;
    }
    if (a.rfind("revoke ", 0) == 0) {
        std::string id = a.substr(7);
        while (!id.empty() && id.front() == ' ') id.erase(id.begin());
        storageSet("lxmproxy.acct.remove", id.c_str());
        cliPrintf("revoking %s\n", id.c_str());
        return;
    }
    if (a == "announce") { serverAnnounce(); cliPrintf("announced\n"); return; }
    cliPrintf("unknown subcommand `%s`. try `lxmproxy -h`.\n", a.c_str());
}

/* ─────────────── the task ─────────────── */

static void lxmproxyTask(void*)
{
    itsServerInit();
    itsClientInit(4);
    itsServerPortOpen(LXMPROXY_CHAN_PORT, ITS_PACKET, LXMPROXY_MAX_SESSIONS,
                      4096, 4096, 0, 4096);
    itsServerOnConnect(LXMPROXY_CHAN_PORT,    onChanConnect);
    itsServerOnRecv(LXMPROXY_CHAN_PORT,       onChanRecv);
    itsServerOnDisconnect(LXMPROXY_CHAN_PORT, onChanDisc);
    /* A frame past one Channel message rides a Resource on the hidden Link;
     * rnsd delivers its lifecycle on the port every link consumer shares. */
    itsServerPortOpen(RNSD_LINK_RESOURCE_AUX_PORT, /*packetBased=*/false,
                      /*maxHandles=*/1, /*toSize=*/0, /*fromSize=*/0);
    itsOnAux(RNSD_LINK_RESOURCE_AUX_PORT, onResourceAux);

    /* The enable switch is watched, not polled — the toggle both flags the
     * reconcile and wakes the wait below. */
    storageSubscribeChanges("s.lxmproxy.enabled",
        [](const char*, const char*) { s_enableDirty = true; });
    /* lxmf's own store is where the work appears: an inbound message landing,
     * or an outbound status moving. Mark every session dirty and let the loop
     * do the scan, so a burst of leaf writes costs one pass. */
    storageSubscribeChanges("s.lxmf.id.",
        [](const char*, const char*) { s_storeDirty = true; });

  for (;;) {
    s_wanted = storageGetInt("s.lxmproxy.enabled", 0) != 0;
    if (s_wanted && s_destHandle < 0) serverOpen();
    s_nextSweep_s = nowS() + LXMPROXY_SWEEP_PERIOD_S;

    while (!s_stop) {
        itsPoll(pdMS_TO_TICKS(1000));

        if (s_enableDirty) {
            s_enableDirty = false;
            s_wanted = storageGetInt("s.lxmproxy.enabled", 0) != 0;
            if (s_wanted && s_destHandle < 0) serverOpen();
            else if (!s_wanted && s_destHandle >= 0) serverClose();
        }
        if (s_destHandle < 0) continue;

        uint32_t now_s = nowS();
        bool store_dirty = s_storeDirty;
        s_storeDirty = false;

        bool serves_dirty = s_servesDirty;
        s_servesDirty = false;

        for (auto& s : s_sessions) {
            if (!s.used) continue;
            if (!s.have_ident) { sessIdentify(s); continue; }
            /* An account the operator has just un-approved stops being served
             * here — the identity slot goes, and its address with it. The
             * revoke sentinel only edits the list; this is where it takes. */
            if (serves_dirty && s.serving && !servesHas(s.ident_hex)) {
                info("[%s] %s revoked — taking its address off the air here",
                     TAG, s.dest_hex.c_str());
                s.releasing_slot   = s.slot;
                s.slot             = -1;
                s.serving          = false;
                s.awaiting_release = true;
                s.id_deadline_s    = now_s + LXMPROXY_IDENTITY_WAIT_S;
                s.sent_status.clear();
                s.sent_msg_s.clear();
                lxmfDestroyIdentity(s.releasing_slot, /*sync=*/false);
            }
            /* Just approved, and the client is sitting on the Channel waiting
             * to be told so. Re-offer: its HANDOVER follows and the account is
             * proxied without the user asking a second time. */
            if (serves_dirty && !s.serving && !s.awaiting_import &&
                !s.awaiting_release && servesHas(s.ident_hex)) {
                info("[%s] %s approved — inviting the handover", TAG, s.dest_hex.c_str());
                sessHello(s);
            }
            if (s.awaiting_import || s.awaiting_release) { sessIdentityTick(s); continue; }
            if (store_dirty) s.dirty = true;
            if (s.serving && (s.dirty || now_s >= s.next_scan_s)) {
                s.dirty = false;
                s.next_scan_s = now_s + LXMPROXY_SCAN_PERIOD_S;
                pushScan(s);
            }
        }
        publishAccounts();

        if (now_s >= s_nextSweep_s) {
            s_nextSweep_s = now_s + LXMPROXY_SWEEP_PERIOD_S;
            retentionSweep();
        }
    }

    serverClose();
    s_parked = true;
    while (s_stop) ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    s_parked = false;
  }
}

/* ── RNS lifecycle hooks ── */

static void lxmproxyStart(void)
{
    s_stop = false;
    if (!s_task)
        s_task = spawnTask(lxmproxyTask, TAG, 8192, nullptr, 1, 0, STACK_PSRAM);
    else
        xTaskNotifyGive(s_task);
}

static void lxmproxyStop(void)
{
    if (!s_task || s_stop) return;
    s_stop = true;
    xTaskNotifyGive(s_task);
    for (int i = 0; i < 300 && !s_parked; i++) delay(10);
    if (!s_parked) warn("[%s] stop timed out", TAG);
}

void LxmproxyService::onInit()
{
    if (storageGetInt("s.lxmproxy.version", 0) < LXMPROXY_VERSION) {
        storageBegin();
        /* Off by default: holding somebody's account is a role a node is given,
         * not a capability every node that ships the code should assume. */
        storageDefault("s.lxmproxy.enabled", 0);
        storageDefault("s.lxmproxy.label", "");
        storageDefault("s.lxmproxy.quota_kb", 64);
        storageDefault("s.lxmproxy.max_envelope_kb", 32);
        storageDefault("s.lxmproxy.retain_days", 7);
        storageDefault("s.lxmproxy.keep_handed", 0);
        storageDefault("s.lxmproxy.inline_bytes", 0);
        storageDefaultTree("s.lxmproxy", "{\"serves\":[]}");
        storageSet("s.lxmproxy.version", LXMPROXY_VERSION);
        storageEnd();
    }

    storageSubscribeChanges("lxmproxy.acct.add",    acctSentinel, /*onStorageTask*/true);
    storageSubscribeChanges("lxmproxy.acct.set",    acctSentinel, /*onStorageTask*/true);
    storageSubscribeChanges("lxmproxy.acct.remove", acctSentinel, /*onStorageTask*/true);

    /* The box's proxy identity exists from boot, so its address is publishable
     * before the server is ever switched on — an operator can read it off the
     * pane and put it into a client without starting anything. */
    rnsdIdentityGenerate(LXMPROXY_IDENTITY_KEY);
    publishDest();
    storageSet("lxmproxy.label", serverLabel().c_str());

    cliRegisterCmd("lxmproxy", cliLxmproxy);

    rnsServiceRegister(TAG, lxmproxyStart, lxmproxyStop);
}
