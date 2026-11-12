/* SPDX-License-Identifier: GPL-3.0-or-later */
/**
 * @file test_detect.c
 * @brief Host tests of ww_detect: the parsing and every rule, with frames made up here.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ww_detect.h"

#define FC0(type, subtype)  ((uint8_t)(((uint32_t)(subtype) << 4U) | ((uint32_t)(type) << 2U)))   /**< Frame control byte 0. */

static ww_detect_t s_d;   /**< The detector under test; large, so not on the stack. */

static const uint8_t AP[WW_ADDR_LEN]    = { 0x02U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U };   /**< An access point. */
static const uint8_t STA[WW_ADDR_LEN]   = { 0x02U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU };   /**< A station. */
static const uint8_t BCAST[WW_ADDR_LEN] = { 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU };   /**< Everyone. */

/**
 * @brief A management frame.
 * @param f       Receives it.
 * @param subtype Its subtype.
 * @param a1      Address 1.
 * @param a2      Address 2.
 */
static void mgmt(ww_frame_t *f, uint8_t subtype, const uint8_t *a1, const uint8_t *a2)
{
    (void)memset(f, 0, sizeof(*f));
    f->channel = 6U;
    f->rssi    = -40;
    f->fc[0]   = FC0(WW_TYPE_MGMT, subtype);
    (void)memcpy(f->addr1, a1, WW_ADDR_LEN);
    (void)memcpy(f->addr2, a2, WW_ADDR_LEN);
    f->len = 26U;
}

/**
 * @brief A beacon from @p bssid with a timestamp.
 * @param f     Receives it.
 * @param bssid Its transmitter.
 * @param tsf   Its timestamp.
 */
static void beacon(ww_frame_t *f, const uint8_t *bssid, uint64_t tsf)
{
    uint8_t i;

    mgmt(f, WW_SUBTYPE_BEACON, BCAST, bssid);
    for ( i = 0U; 8U > i; i++ )
    {
        f->head[i] = (uint8_t)(tsf >> (8U * i));
    }
    f->len = 120U;
}

/** @brief The parsers. */
static void test_parse(void)
{
    uint8_t fc[2] = { FC0(WW_TYPE_MGMT, WW_SUBTYPE_DEAUTH), 0U };
    uint8_t head[WW_HEAD_LEN] = { 0x07U, 0x00U, 0U, 0U, 0U, 0U, 0U, 0U };
    uint8_t tsf[WW_HEAD_LEN]  = { 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U };
    char    s[WW_MAC_STR_LEN];

    assert(WW_TYPE_MGMT == ww_frame_type(fc));
    assert(WW_SUBTYPE_DEAUTH == ww_frame_subtype(fc));
    fc[0] = 0x88U;   /* a QoS data frame */
    assert(WW_TYPE_DATA == ww_frame_type(fc));
    assert(8U == ww_frame_subtype(fc));
    fc[0] = 0x80U;   /* a beacon, as on the air */
    assert(WW_TYPE_MGMT == ww_frame_type(fc));
    assert(WW_SUBTYPE_BEACON == ww_frame_subtype(fc));

    assert(7U == ww_frame_reason(head));
    assert(0x0807060504030201ULL == ww_frame_tsf(tsf));

    assert(ww_mac_is_broadcast(BCAST));
    assert(!ww_mac_is_broadcast(AP));
    ww_mac_format(AP, s);
    assert(0 == strcmp("02:11:22:33:44:55", s));
}

/** @brief A deauth flood alerts once, with the sender, the target and the reason. */
static void test_deauth_flood(void)
{
    ww_frame_t f;
    uint32_t   t;
    uint32_t   raised = 0U;
    const ww_alert_t *a;

    ww_detect_init(&s_d);
    mgmt(&f, WW_SUBTYPE_DEAUTH, BCAST, AP);
    f.head[0] = 7U;   /* class 3 frame from a nonassociated station */
    for ( t = 0U; 30U > t; t++ )
    {
        if ( ww_detect_frame(&s_d, &f, 1000U + (t * 20U)) )
        {
            raised++;
        }
    }
    assert(1U == raised);
    assert(1U == ww_detect_alert_count(&s_d));
    a = ww_detect_alert(&s_d, 0U);
    assert(NULL != a);
    assert(WW_ALERT_DEAUTH_FLOOD == a->kind);
    assert(0 == memcmp(a->src, AP, WW_ADDR_LEN));
    assert(ww_mac_is_broadcast(a->dst));
    assert(7U == a->reason);
    assert(!a->protected_mgmt);
    assert(WW_FLOOD_THRESHOLD <= a->count);
    assert(30U == ww_detect_counts(&s_d)->deauths);
    assert(1U == ww_detect_active(&s_d, 2000U));
    assert(0U == ww_detect_active(&s_d, 2000U + WW_CLEAR_MS));
}

/** @brief A few deauths, a client leaving, alert nothing; nor does a slow trickle. */
static void test_deauth_quiet(void)
{
    ww_frame_t f;
    uint32_t   t;

    ww_detect_init(&s_d);
    mgmt(&f, WW_SUBTYPE_DEAUTH, AP, STA);
    for ( t = 0U; 3U > t; t++ )
    {
        assert(!ww_detect_frame(&s_d, &f, 1000U + t));
    }
    /* One every 200 ms: 5 a window, under the threshold, for a minute. */
    for ( t = 0U; 300U > t; t++ )
    {
        assert(!ww_detect_frame(&s_d, &f, 5000U + (t * 200U)));
    }
    assert(0U == ww_detect_alert_count(&s_d));
}

/** @brief A protected disassoc flood: its own kind, and no reason to read. */
static void test_disassoc_protected(void)
{
    ww_frame_t f;
    uint32_t   t;
    const ww_alert_t *a;

    ww_detect_init(&s_d);
    mgmt(&f, WW_SUBTYPE_DISASSOC, STA, AP);
    f.fc[1]   = WW_FC1_PROTECTED;
    f.head[0] = 0x5AU;   /* ciphertext */
    for ( t = 0U; WW_FLOOD_THRESHOLD > t; t++ )
    {
        (void)ww_detect_frame(&s_d, &f, 100U + t);
    }
    a = ww_detect_alert(&s_d, 0U);
    assert(NULL != a);
    assert(WW_ALERT_DISASSOC_FLOOD == a->kind);
    assert(a->protected_mgmt);
    assert(0U == a->reason);
    assert(0 == memcmp(a->dst, STA, WW_ADDR_LEN));
}

/** @brief A flood that stops and comes back after the all clear is raised again. */
static void test_alert_comes_back(void)
{
    ww_frame_t f;
    uint32_t   t;
    uint32_t   raised = 0U;

    ww_detect_init(&s_d);
    mgmt(&f, WW_SUBTYPE_DEAUTH, BCAST, AP);
    for ( t = 0U; 20U > t; t++ )
    {
        raised += (uint32_t)ww_detect_frame(&s_d, &f, 1000U + t);
    }
    for ( t = 0U; 20U > t; t++ )
    {
        raised += (uint32_t)ww_detect_frame(&s_d, &f, 1000U + WW_CLEAR_MS + 5000U + t);
    }
    assert(2U == raised);
    assert(1U == ww_detect_alert_count(&s_d));
}

/** @brief Many new BSSIDs after the settle are a beacon flood; the same number at a hop is not. */
static void test_beacon_flood(void)
{
    ww_frame_t f;
    uint8_t    mac[WW_ADDR_LEN] = { 0x02U, 0U, 0U, 0U, 0U, 0U };
    uint32_t   i;
    bool       raised = false;

    /* At the hop: thirty networks on the channel, learnt in the settle, no alert. */
    ww_detect_init(&s_d);
    ww_detect_channel(&s_d, 6U, 1000U);
    for ( i = 0U; 30U > i; i++ )
    {
        mac[5] = (uint8_t)i;
        beacon(&f, mac, 1000000U + i);
        assert(!ww_detect_frame(&s_d, &f, 1000U + (i * 20U)));
    }
    /* Heard again later: known, no alert. */
    for ( i = 0U; 30U > i; i++ )
    {
        mac[5] = (uint8_t)i;
        beacon(&f, mac, 2000000U + i);
        assert(!ww_detect_frame(&s_d, &f, 3000U + (i * 20U)));
    }
    assert(0U == ww_detect_alert_count(&s_d));

    /* After the settle, forty random BSSIDs in a second. */
    mac[4] = 0x99U;
    for ( i = 0U; 40U > i; i++ )
    {
        mac[5] = (uint8_t)i;
        beacon(&f, mac, 5000U);
        if ( ww_detect_frame(&s_d, &f, 5000U + (i * 25U)) )
        {
            raised = true;
        }
    }
    assert(raised);
    assert(WW_ALERT_BEACON_FLOOD == ww_detect_alert(&s_d, 0U)->kind);
}

/** @brief Two transmitters on one BSSID step its timestamp back and forth; a reboot steps it back once. */
static void test_bssid_clone(void)
{
    ww_frame_t f;
    uint32_t   i;
    bool       raised = false;

    /* A reboot: one step back, then forward again. */
    ww_detect_init(&s_d);
    beacon(&f, AP, 900000000ULL);
    (void)ww_detect_frame(&s_d, &f, 100U);
    beacon(&f, AP, 900102400ULL);
    (void)ww_detect_frame(&s_d, &f, 200U);
    beacon(&f, AP, 1000U);
    (void)ww_detect_frame(&s_d, &f, 300U);
    for ( i = 1U; 50U > i; i++ )
    {
        beacon(&f, AP, 1000U + (i * 102400U));
        assert(!ww_detect_frame(&s_d, &f, 300U + (i * 102U)));
    }
    assert(0U == ww_detect_alert_count(&s_d));

    /* A clone: two clocks, interleaved. */
    ww_detect_init(&s_d);
    for ( i = 0U; 10U > i; i++ )
    {
        beacon(&f, AP, 900000000ULL + (i * 102400U));   /* the real one, up for 15 minutes */
        raised = raised || ww_detect_frame(&s_d, &f, 100U + (i * 102U));
        beacon(&f, AP, 5000000ULL + (i * 102400U));     /* the twin, up for 5 seconds */
        raised = raised || ww_detect_frame(&s_d, &f, 150U + (i * 102U));
    }
    assert(raised);
    assert(WW_ALERT_BSSID_CLONE == ww_detect_alert(&s_d, 0U)->kind);
    assert(0 == memcmp(ww_detect_alert(&s_d, 0U)->src, AP, WW_ADDR_LEN));

    /* A beacon cut before its timestamp (all zeros) is not a step back. */
    ww_detect_init(&s_d);
    beacon(&f, AP, 900000000ULL);
    (void)ww_detect_frame(&s_d, &f, 100U);
    for ( i = 0U; 10U > i; i++ )
    {
        beacon(&f, AP, 0U);
        assert(!ww_detect_frame(&s_d, &f, 200U + i));
    }
}

/** @brief A name both open and secured is a twin; the open BSSID is named. */
static void test_twin_security(void)
{
    static const uint8_t TWIN[WW_ADDR_LEN] = { 0x02U, 0x66U, 0x66U, 0x66U, 0x66U, 0x66U };
    const ww_alert_t *a;

    ww_detect_init(&s_d);
    assert(!ww_detect_scan_entry(&s_d, "CoffeeShop", AP, 6U, false, -50, 100U));
    assert(ww_detect_scan_entry(&s_d, "CoffeeShop", TWIN, 11U, true, -30, 110U));
    a = ww_detect_alert(&s_d, 0U);
    assert(NULL != a);
    assert(WW_ALERT_TWIN_SECURITY == a->kind);
    assert(0 == strcmp("CoffeeShop", a->ssid));
    assert(0 == memcmp(a->src, TWIN, WW_ADDR_LEN));
    assert(WW_SEV_ALERT == ww_alert_severity(a->kind));

    /* The next scan sees the same: one alert, still held, not raised again. */
    ww_detect_scan_done(&s_d);
    assert(!ww_detect_scan_entry(&s_d, "CoffeeShop", AP, 6U, false, -50, 60000U));
    assert(!ww_detect_scan_entry(&s_d, "CoffeeShop", TWIN, 11U, true, -30, 60010U));
    assert(1U == ww_detect_alert_count(&s_d));
}

/** @brief A mesh of one name, all secured, is fine; a BSSID new after the baseline is a warning. */
static void test_twin_new_bssid(void)
{
    static const uint8_t AP2[WW_ADDR_LEN] = { 0x02U, 0x11U, 0x22U, 0x33U, 0x44U, 0x56U };
    static const uint8_t NEW[WW_ADDR_LEN] = { 0x0AU, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U };
    ww_severity_t sev = WW_SEV_ALERT;

    ww_detect_init(&s_d);
    assert(!ww_detect_scan_entry(&s_d, "Home", AP, 1U, false, -50, 100U));
    assert(!ww_detect_scan_entry(&s_d, "Home", AP2, 36U, false, -60, 100U));
    assert(!ww_detect_scan_entry(&s_d, "", NEW, 6U, true, -60, 100U));   /* hidden: ignored */
    ww_detect_scan_done(&s_d);
    assert(0U == ww_detect_alert_count(&s_d));
    assert(!ww_detect_worst(&s_d, 200U, &sev));

    /* A name first seen in this scan has no baseline: no warning for it. */
    assert(!ww_detect_scan_entry(&s_d, "Guest", NEW, 6U, false, -60, 60000U));
    assert(ww_detect_scan_entry(&s_d, "Home", NEW, 6U, false, -35, 60000U));
    assert(WW_ALERT_TWIN_NEW_BSSID == ww_detect_alert(&s_d, 0U)->kind);
    assert(ww_detect_worst(&s_d, 60001U, &sev));
    assert(WW_SEV_WARN == sev);
}

/** @brief The list keeps the newest WW_ALERT_MAX, the one seen last first; clearing keeps the counts. */
static void test_alert_list(void)
{
    ww_frame_t f;
    uint8_t    src[WW_ADDR_LEN] = { 0x02U, 0x01U, 0U, 0U, 0U, 0U };
    uint32_t   i;
    uint32_t   t;
    uint32_t   now = 1000U;

    ww_detect_init(&s_d);
    for ( i = 0U; (WW_ALERT_MAX + 4U) > i; i++ )
    {
        src[5] = (uint8_t)i;
        mgmt(&f, WW_SUBTYPE_DEAUTH, BCAST, src);
        for ( t = 0U; WW_FLOOD_THRESHOLD > t; t++ )
        {
            (void)ww_detect_frame(&s_d, &f, now);
            now++;
        }
    }
    assert(WW_ALERT_MAX == ww_detect_alert_count(&s_d));
    assert((WW_ALERT_MAX + 3U) == ww_detect_alert(&s_d, 0U)->src[5]);
    assert(4U == ww_detect_alert(&s_d, WW_ALERT_MAX - 1U)->src[5]);
    assert(NULL == ww_detect_alert(&s_d, WW_ALERT_MAX));
    ww_detect_clear_alerts(&s_d);
    assert(0U == ww_detect_alert_count(&s_d));
    assert(0U < ww_detect_counts(&s_d)->deauths);
}

/** @brief The counts follow the kinds; a control frame is counted as a frame only. */
static void test_counts(void)
{
    ww_frame_t f;

    ww_detect_init(&s_d);
    mgmt(&f, WW_SUBTYPE_PROBE_RSP, STA, AP);
    (void)ww_detect_frame(&s_d, &f, 1U);
    f.fc[0] = 0x88U;
    (void)ww_detect_frame(&s_d, &f, 2U);
    f.fc[0] = FC0(WW_TYPE_CTRL, 0xBU);
    (void)ww_detect_frame(&s_d, &f, 3U);
    assert(3U == ww_detect_counts(&s_d)->frames);
    assert(1U == ww_detect_counts(&s_d)->mgmt);
    assert(1U == ww_detect_counts(&s_d)->data);
    assert(0U == ww_detect_counts(&s_d)->beacons);
    assert(0 == strcmp("Deauth flood", ww_alert_name(WW_ALERT_DEAUTH_FLOOD)));
    assert(0 == strcmp("Alert", ww_alert_name(WW_ALERT_KIND_COUNT)));
}

/** @brief Times that wrap past 2^32 ms still count windows right. */
static void test_wrap(void)
{
    ww_frame_t f;
    uint32_t   t;
    bool       raised = false;

    ww_detect_init(&s_d);
    mgmt(&f, WW_SUBTYPE_DEAUTH, BCAST, AP);
    for ( t = 0U; 20U > t; t++ )
    {
        raised = raised || ww_detect_frame(&s_d, &f, 0xFFFFFF00U + (t * 20U));
    }
    assert(raised);
}

/**
 * @brief Run every test.
 * @return 0.
 */
int main(void)
{
    test_parse();
    test_deauth_flood();
    test_deauth_quiet();
    test_disassoc_protected();
    test_alert_comes_back();
    test_beacon_flood();
    test_bssid_clone();
    test_twin_security();
    test_twin_new_bssid();
    test_alert_list();
    test_counts();
    test_wrap();
    (void)printf("ww_detect: all tests passed\n");
    return 0;
}
