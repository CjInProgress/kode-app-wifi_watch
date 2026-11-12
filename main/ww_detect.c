/* SPDX-License-Identifier: GPL-3.0-or-later */
/**
 * @file ww_detect.c
 * @brief Wi-Fi Watch's detector: frame parsing and the attack rules, plain C with no SDK call.
 */
#include "ww_detect.h"

#include <string.h>

#define WW_FC0_TYPE_SHIFT     2U     /**< Where the type sits in frame control byte 0.    */
#define WW_FC0_TYPE_MASK      0x3U   /**< The type's two bits.                             */
#define WW_FC0_SUBTYPE_SHIFT  4U     /**< Where the subtype sits in frame control byte 0.  */
#define WW_FC0_SUBTYPE_MASK   0xFU   /**< The subtype's four bits.                         */
#define WW_TSF_LEN            8U     /**< Bytes of a beacon's timestamp.                   */
#define WW_REASON_LEN         2U     /**< Bytes of a deauth's reason code.                 */
#define WW_BITS_PER_BYTE      8U     /**< Bits in a byte.                                  */
#define WW_BROADCAST_BYTE     0xFFU  /**< Every byte of the broadcast address.             */
#define WW_NIBBLE_SHIFT       4U     /**< The high half of a byte.                         */
#define WW_NIBBLE_MASK        0xFU   /**< A half byte.                                     */
#define WW_COUNT_MAX          0xFFFFU /**< The most a uint16_t count holds.                */

_Static_assert(WW_TSF_LEN <= WW_HEAD_LEN, "a beacon's timestamp fits the head the C5 keeps");
_Static_assert(WW_REASON_LEN <= WW_HEAD_LEN, "a deauth's reason fits the head the C5 keeps");
_Static_assert(WW_MAC_STR_LEN == ((WW_ADDR_LEN * 3U)), "two digits and a colon per byte, the last colon the NUL");
_Static_assert(WW_ALERT_MAX <= 255U, "n_alerts is a uint8_t");

/** @brief The names on the screen, by kind. */
static const char * const s_names[WW_ALERT_KIND_COUNT] = {
    "Deauth flood",
    "Disassoc flood",
    "Beacon flood",
    "BSSID clone",
    "Twin: open + secured",
    "Twin: new BSSID",
};

/** @brief The all-zero address: an alert that names no address. */
static const uint8_t s_none[WW_ADDR_LEN] = { 0U, 0U, 0U, 0U, 0U, 0U };

/* ---- Small helpers ------------------------------------------------------- */

/**
 * @brief Time between two readings, wrap-safe.
 * @param now  The later reading.
 * @param then The earlier one.
 * @return now - then, as uint32_t.
 */
static uint32_t since(uint32_t now, uint32_t then)
{
    return (uint32_t)(now - then);
}

/**
 * @brief Whether two addresses are the same.
 * @param a One.
 * @param b The other.
 * @return true when every byte matches.
 */
static bool mac_eq(const uint8_t a[WW_ADDR_LEN], const uint8_t b[WW_ADDR_LEN])
{
    return 0 == memcmp(a, b, WW_ADDR_LEN);
}

/**
 * @brief Copy a network name, cut to fit and always terminated.
 * @param dst  Receives it; WW_SSID_MAX bytes.
 * @param ssid The name, or NULL for "".
 */
static void ssid_copy(char dst[WW_SSID_MAX], const char *ssid)
{
    (void)memset(dst, 0, WW_SSID_MAX);
    if ( NULL != ssid )
    {
        (void)strncpy(dst, ssid, WW_SSID_MAX - 1U);
    }
}

/* ---- Frame parsing ------------------------------------------------------- */

uint8_t ww_frame_type(const uint8_t fc[WW_FC_LEN])
{
    return (uint8_t)((fc[0] >> WW_FC0_TYPE_SHIFT) & WW_FC0_TYPE_MASK);
}

uint8_t ww_frame_subtype(const uint8_t fc[WW_FC_LEN])
{
    return (uint8_t)((fc[0] >> WW_FC0_SUBTYPE_SHIFT) & WW_FC0_SUBTYPE_MASK);
}

uint64_t ww_frame_tsf(const uint8_t head[WW_HEAD_LEN])
{
    uint64_t tsf = 0U;
    uint8_t  i;

    /* Little-endian on the air: the last byte is the most significant. */
    for ( i = WW_TSF_LEN; 0U < i; i-- )
    {
        tsf = (tsf << WW_BITS_PER_BYTE) | (uint64_t)head[i - 1U];
    }
    return tsf;
}

uint16_t ww_frame_reason(const uint8_t head[WW_HEAD_LEN])
{
    return (uint16_t)((uint16_t)head[0] | (uint16_t)((uint16_t)head[1] << WW_BITS_PER_BYTE));
}

bool ww_mac_is_broadcast(const uint8_t mac[WW_ADDR_LEN])
{
    bool    all = true;
    uint8_t i;

    for ( i = 0U; WW_ADDR_LEN > i; i++ )
    {
        if ( WW_BROADCAST_BYTE != mac[i] )
        {
            all = false;
        }
    }
    return all;
}

void ww_mac_format(const uint8_t mac[WW_ADDR_LEN], char out[WW_MAC_STR_LEN])
{
    static const char hex[] = "0123456789abcdef";
    uint8_t i;

    for ( i = 0U; WW_ADDR_LEN > i; i++ )
    {
        out[i * 3U]       = hex[(mac[i] >> WW_NIBBLE_SHIFT) & WW_NIBBLE_MASK];
        out[(i * 3U) + 1U] = hex[mac[i] & WW_NIBBLE_MASK];
        out[(i * 3U) + 2U] = ':';
    }
    out[WW_MAC_STR_LEN - 1U] = '\0';
}

/* ---- Alerts -------------------------------------------------------------- */

/**
 * @brief Raise an alert, or update the one already held about the same thing.
 *
 * An alert is about a kind, two addresses and a name. Seen again, the one
 * held moves to the end (the one seen last) and keeps its first time; it
 * counts as raised only when it had been quiet for WW_CLEAR_MS. When the
 * list is full the oldest goes.
 *
 * @param d      The detector.
 * @param tmpl   What the alert says; its first_ms and last_ms are ignored.
 * @param now_ms The time.
 * @return true when raised.
 */
static bool alert_raise(ww_detect_t *d, const ww_alert_t *tmpl, uint32_t now_ms)
{
    ww_alert_t a;
    bool       raised = true;
    uint8_t    i;
    uint8_t    found  = WW_ALERT_MAX;

    for ( i = 0U; i < d->n_alerts; i++ )
    {
        ww_alert_t const * const h = &d->alerts[i];

        if ( (h->kind == tmpl->kind) && mac_eq(h->src, tmpl->src) && mac_eq(h->dst, tmpl->dst)
             && (0 == strncmp(h->ssid, tmpl->ssid, WW_SSID_MAX)) )
        {
            found = i;
        }
    }

    a = *tmpl;
    a.first_ms = now_ms;
    a.last_ms  = now_ms;
    if ( WW_ALERT_MAX != found )
    {
        ww_alert_t const * const h = &d->alerts[found];

        if ( WW_CLEAR_MS > since(now_ms, h->last_ms) )
        {
            raised     = false;
            a.first_ms = h->first_ms;
        }
        if ( h->count > a.count )
        {
            a.count = h->count;
        }
        /* Take it out; it goes back at the end below. */
        for ( i = found; (uint8_t)(i + 1U) < d->n_alerts; i++ )
        {
            d->alerts[i] = d->alerts[i + 1U];
        }
        d->n_alerts--;
    }
    else if ( WW_ALERT_MAX == d->n_alerts )
    {
        for ( i = 0U; (uint8_t)(i + 1U) < d->n_alerts; i++ )
        {
            d->alerts[i] = d->alerts[i + 1U];
        }
        d->n_alerts--;
    }
    else
    {
        /* Room at the end. */
    }
    d->alerts[d->n_alerts] = a;
    d->n_alerts++;
    return raised;
}

/**
 * @brief A blank alert of a kind, heard on a channel.
 * @param a    Receives it.
 * @param kind The kind.
 * @param ch   The channel.
 * @param rssi The strength.
 */
static void alert_blank(ww_alert_t *a, ww_alert_kind_t kind, uint8_t ch, int8_t rssi)
{
    (void)memset(a, 0, sizeof(*a));
    a->kind    = kind;
    a->channel = ch;
    a->rssi    = rssi;
}

/* ---- The rules ----------------------------------------------------------- */

/**
 * @brief A deauthentication or disassociation: follow its pair's rate.
 * @param d       The detector.
 * @param f       The frame.
 * @param subtype WW_SUBTYPE_DEAUTH or WW_SUBTYPE_DISASSOC.
 * @param now_ms  The time.
 * @return true when it raised an alert.
 */
static bool rule_deauth(ww_detect_t *d, const ww_frame_t *f, uint8_t subtype, uint32_t now_ms)
{
    ww_pair_t *p      = NULL;
    ww_pair_t *oldest = &d->pairs[0];
    bool       raised = false;
    uint8_t    i;

    for ( i = 0U; WW_PAIR_MAX > i; i++ )
    {
        ww_pair_t * const q = &d->pairs[i];

        if ( q->used && (q->subtype == subtype) && mac_eq(q->src, f->addr2) && mac_eq(q->dst, f->addr1) )
        {
            p = q;
        }
        /* An unused slot is the oldest of all. */
        if ( (!q->used) || (oldest->used && (since(now_ms, q->last_ms) > since(now_ms, oldest->last_ms))) )
        {
            oldest = q;
        }
    }
    if ( NULL == p )
    {
        p = oldest;
        (void)memset(p, 0, sizeof(*p));
        p->used      = true;
        p->subtype   = subtype;
        p->window_ms = now_ms;
        (void)memcpy(p->src, f->addr2, WW_ADDR_LEN);
        (void)memcpy(p->dst, f->addr1, WW_ADDR_LEN);
    }
    if ( WW_FLOOD_WINDOW_MS <= since(now_ms, p->window_ms) )
    {
        p->window_ms = now_ms;
        p->count     = 0U;
    }
    if ( WW_COUNT_MAX > p->count )
    {
        p->count++;
    }
    p->last_ms = now_ms;

    if ( WW_FLOOD_THRESHOLD <= p->count )
    {
        ww_alert_t a;
        ww_alert_kind_t kind = WW_ALERT_DEAUTH_FLOOD;

        if ( WW_SUBTYPE_DISASSOC == subtype )
        {
            kind = WW_ALERT_DISASSOC_FLOOD;
        }
        alert_blank(&a, kind, f->channel, f->rssi);
        (void)memcpy(a.src, f->addr2, WW_ADDR_LEN);
        (void)memcpy(a.dst, f->addr1, WW_ADDR_LEN);
        a.count = p->count;
        if ( 0U != (f->fc[1] & WW_FC1_PROTECTED) )
        {
            a.protected_mgmt = true;
        }
        else
        {
            a.reason = ww_frame_reason(f->head);
        }
        raised = alert_raise(d, &a, now_ms);
    }
    return raised;
}

/**
 * @brief Count one BSSID never heard before towards a beacon flood.
 * @param d      The detector.
 * @param f      Its beacon.
 * @param now_ms The time.
 * @return true when it raised an alert.
 */
static bool rule_new_bssid(ww_detect_t *d, const ww_frame_t *f, uint32_t now_ms)
{
    bool raised = false;

    /* Just after a hop every BSSID is new to the window: learn them first. */
    if ( WW_SETTLE_MS <= since(now_ms, d->channel_ms) )
    {
        if ( WW_BEACON_WINDOW_MS <= since(now_ms, d->new_window_ms) )
        {
            d->new_window_ms = now_ms;
            d->new_count     = 0U;
        }
        if ( WW_COUNT_MAX > d->new_count )
        {
            d->new_count++;
        }
        if ( WW_BEACON_THRESHOLD <= d->new_count )
        {
            ww_alert_t a;

            alert_blank(&a, WW_ALERT_BEACON_FLOOD, f->channel, f->rssi);
            a.count = d->new_count;
            raised  = alert_raise(d, &a, now_ms);
        }
    }
    return raised;
}

/**
 * @brief A beacon: learn its BSSID, and watch its timestamp go only forward.
 *
 * An access point's timestamp counts microseconds up from its start. Two
 * transmitters beaconing the same BSSID each send their own, so the beacons
 * heard step back and forth; one that reboots steps back once.
 *
 * @param d      The detector.
 * @param f      The beacon.
 * @param now_ms The time.
 * @return true when it raised an alert.
 */
static bool rule_beacon(ww_detect_t *d, const ww_frame_t *f, uint32_t now_ms)
{
    ww_bssid_t    *b      = NULL;
    ww_bssid_t    *oldest = &d->bssids[0];
    bool           raised = false;
    uint64_t const tsf    = ww_frame_tsf(f->head);
    uint8_t        i;

    for ( i = 0U; WW_BSSID_MAX > i; i++ )
    {
        ww_bssid_t * const q = &d->bssids[i];

        if ( q->used && mac_eq(q->bssid, f->addr2) )
        {
            b = q;
        }
        if ( (!q->used) || (oldest->used && (since(now_ms, q->last_ms) > since(now_ms, oldest->last_ms))) )
        {
            oldest = q;
        }
    }

    if ( NULL == b )
    {
        b = oldest;
        (void)memset(b, 0, sizeof(*b));
        b->used = true;
        (void)memcpy(b->bssid, f->addr2, WW_ADDR_LEN);
        b->tsf  = tsf;
        raised  = rule_new_bssid(d, f, now_ms);
    }
    else if ( 0U != tsf )
    {
        if ( tsf < b->tsf )
        {
            if ( (0U == b->back) || (WW_TSF_WINDOW_MS <= since(now_ms, b->back_ms)) )
            {
                b->back_ms = now_ms;
                b->back    = 0U;
            }
            b->back++;
            if ( WW_TSF_THRESHOLD <= b->back )
            {
                ww_alert_t a;

                alert_blank(&a, WW_ALERT_BSSID_CLONE, f->channel, f->rssi);
                (void)memcpy(a.src, f->addr2, WW_ADDR_LEN);
                a.count = b->back;
                raised  = alert_raise(d, &a, now_ms);
            }
        }
        b->tsf = tsf;
    }
    else
    {
        /* A beacon cut before its timestamp says nothing about it. */
    }
    b->last_ms = now_ms;
    return raised;
}

/* ---- The detector -------------------------------------------------------- */

void ww_detect_init(ww_detect_t *d)
{
    (void)memset(d, 0, sizeof(*d));
}

void ww_detect_channel(ww_detect_t *d, uint8_t channel, uint32_t now_ms)
{
    d->channel       = channel;
    d->channel_ms    = now_ms;
    d->new_window_ms = now_ms;
    d->new_count     = 0U;
}

bool ww_detect_frame(ww_detect_t *d, const ww_frame_t *f, uint32_t now_ms)
{
    uint8_t const type    = ww_frame_type(f->fc);
    uint8_t const subtype = ww_frame_subtype(f->fc);
    bool          raised  = false;

    d->counts.frames++;
    if ( WW_TYPE_DATA == type )
    {
        d->counts.data++;
    }
    else if ( WW_TYPE_MGMT == type )
    {
        d->counts.mgmt++;
        if ( (WW_SUBTYPE_DEAUTH == subtype) || (WW_SUBTYPE_DISASSOC == subtype) )
        {
            d->counts.deauths++;
            raised = rule_deauth(d, f, subtype, now_ms);
        }
        else if ( WW_SUBTYPE_BEACON == subtype )
        {
            d->counts.beacons++;
            /* A beacon with no transmitter is malformed: nothing to follow. */
            if ( !mac_eq(f->addr2, s_none) )
            {
                raised = rule_beacon(d, f, now_ms);
            }
        }
        else
        {
            /* Probes, authentications and the rest: counted only. */
        }
    }
    else
    {
        /* The C5 asks for no control frames; anything else is counted only. */
    }
    return raised;
}

bool ww_detect_scan_entry(ww_detect_t *d, const char *ssid, const uint8_t bssid[WW_ADDR_LEN],
                          uint8_t channel, bool open, int8_t rssi, uint32_t now_ms)
{
    ww_net_t *n      = NULL;
    ww_net_t *free_n = NULL;
    bool      raised = false;
    bool      known  = false;
    bool      any_open    = false;
    bool      any_secured = false;
    uint8_t   i;

    if ( (NULL == ssid) || ('\0' == ssid[0]) )
    {
        return false;   /* a hidden network has no name to be twinned */
    }
    for ( i = 0U; WW_NET_MAX > i; i++ )
    {
        ww_net_t * const q = &d->nets[i];

        if ( q->used && (0 == strncmp(q->ssid, ssid, WW_SSID_MAX - 1U)) )
        {
            n = q;
        }
        if ( (!q->used) && (NULL == free_n) )
        {
            free_n = q;
        }
    }
    if ( NULL == n )
    {
        if ( NULL == free_n )
        {
            return false;   /* the table is full: this name goes unwatched */
        }
        n = free_n;
        (void)memset(n, 0, sizeof(*n));
        n->used = true;
        ssid_copy(n->ssid, ssid);
    }

    for ( i = 0U; i < n->n; i++ )
    {
        if ( mac_eq(n->bssid[i], bssid) )
        {
            known      = true;
            n->open[i] = open;
        }
    }
    if ( !known )
    {
        if ( n->baseline && d->scanned )
        {
            ww_alert_t a;

            alert_blank(&a, WW_ALERT_TWIN_NEW_BSSID, channel, rssi);
            (void)memcpy(a.src, bssid, WW_ADDR_LEN);
            ssid_copy(a.ssid, ssid);
            a.count = (uint16_t)n->n + 1U;
            raised  = alert_raise(d, &a, now_ms);
        }
        if ( WW_NET_BSSID_MAX > n->n )
        {
            (void)memcpy(n->bssid[n->n], bssid, WW_ADDR_LEN);
            n->open[n->n] = open;
            n->n++;
        }
    }

    for ( i = 0U; i < n->n; i++ )
    {
        if ( n->open[i] )
        {
            any_open = true;
        }
        else
        {
            any_secured = true;
        }
    }
    if ( any_open && any_secured )
    {
        ww_alert_t a;

        /* The open one is the likely impostor: a twin needs no password to lure. */
        alert_blank(&a, WW_ALERT_TWIN_SECURITY, channel, rssi);
        for ( i = 0U; i < n->n; i++ )
        {
            if ( n->open[i] && mac_eq(a.src, s_none) )
            {
                (void)memcpy(a.src, n->bssid[i], WW_ADDR_LEN);
            }
        }
        ssid_copy(a.ssid, ssid);
        a.count = n->n;
        if ( alert_raise(d, &a, now_ms) )
        {
            raised = true;
        }
    }
    return raised;
}

void ww_detect_scan_done(ww_detect_t *d)
{
    uint8_t i;

    for ( i = 0U; WW_NET_MAX > i; i++ )
    {
        if ( d->nets[i].used )
        {
            d->nets[i].baseline = true;
        }
    }
    d->scanned = true;
}

uint8_t ww_detect_alert_count(const ww_detect_t *d)
{
    return d->n_alerts;
}

const ww_alert_t *ww_detect_alert(const ww_detect_t *d, uint8_t i)
{
    const ww_alert_t *a = NULL;

    if ( i < d->n_alerts )
    {
        a = &d->alerts[(d->n_alerts - 1U) - i];
    }
    return a;
}

uint8_t ww_detect_active(const ww_detect_t *d, uint32_t now_ms)
{
    uint8_t n = 0U;
    uint8_t i;

    for ( i = 0U; i < d->n_alerts; i++ )
    {
        if ( WW_CLEAR_MS > since(now_ms, d->alerts[i].last_ms) )
        {
            n++;
        }
    }
    return n;
}

bool ww_detect_worst(const ww_detect_t *d, uint32_t now_ms, ww_severity_t *out)
{
    bool    any = false;
    uint8_t i;

    for ( i = 0U; i < d->n_alerts; i++ )
    {
        if ( WW_CLEAR_MS > since(now_ms, d->alerts[i].last_ms) )
        {
            ww_severity_t const s = ww_alert_severity(d->alerts[i].kind);

            if ( (!any) || (s > *out) )
            {
                *out = s;
            }
            any = true;
        }
    }
    return any;
}

ww_severity_t ww_alert_severity(ww_alert_kind_t kind)
{
    ww_severity_t s = WW_SEV_ALERT;

    /* A new BSSID for a known name is how a mesh grows as well as how a twin appears. */
    if ( WW_ALERT_TWIN_NEW_BSSID == kind )
    {
        s = WW_SEV_WARN;
    }
    return s;
}

const char *ww_alert_name(ww_alert_kind_t kind)
{
    const char *name = "Alert";

    if ( WW_ALERT_KIND_COUNT > kind )
    {
        name = s_names[kind];
    }
    return name;
}

const ww_counts_t *ww_detect_counts(const ww_detect_t *d)
{
    return &d->counts;
}

void ww_detect_clear_alerts(ww_detect_t *d)
{
    (void)memset(d->alerts, 0, sizeof(d->alerts));
    d->n_alerts = 0U;
}
