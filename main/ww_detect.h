/* SPDX-License-Identifier: GPL-3.0-or-later */
/**
 * @file ww_detect.h
 * @brief Wi-Fi Watch's detector: frame parsing and the attack rules, plain C with no SDK call.
 *
 * Everything here is data in and data out, so it runs on the host under
 * test/run.sh as well as on the Dot. The Active Object copies each frame the
 * C5 hands over into a ww_frame_t, each network of a scan into
 * ww_detect_scan_entry(), and reads the alerts back. The detector never
 * reads a clock: every call takes the time, in milliseconds, from its caller.
 */
#ifndef WW_DETECT_H_
#define WW_DETECT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Sizes of what a frame carries ---- */

#define WW_ADDR_LEN       6U    /**< Bytes of a MAC address.                                   */
#define WW_FC_LEN         2U    /**< Bytes of the frame control field.                         */
#define WW_HEAD_LEN       8U    /**< Bytes after the MAC header the C5 keeps (KODE_SNIFF_HEAD_LEN). */
#define WW_SSID_MAX       33U   /**< Bytes of a network name, NUL included.                    */
#define WW_MAC_STR_LEN    18U   /**< "aa:bb:cc:dd:ee:ff" and its NUL.                          */

/* ---- 802.11 frame control ---- */

#define WW_TYPE_MGMT          0U     /**< Management frame type.                     */
#define WW_TYPE_CTRL          1U     /**< Control frame type.                        */
#define WW_TYPE_DATA          2U     /**< Data frame type.                           */
#define WW_SUBTYPE_PROBE_RSP  0x5U   /**< Management: probe response.                */
#define WW_SUBTYPE_BEACON     0x8U   /**< Management: beacon.                        */
#define WW_SUBTYPE_DISASSOC   0xAU   /**< Management: disassociation.                */
#define WW_SUBTYPE_DEAUTH     0xCU   /**< Management: deauthentication.              */
#define WW_FC1_PROTECTED      0x40U  /**< Frame control byte 1: the body is encrypted (802.11w for management). */

/* ---- The rules' thresholds ---- */

#define WW_FLOOD_WINDOW_MS        1000U   /**< The window a deauth or disassoc rate is counted over.           */
#define WW_FLOOD_THRESHOLD        10U     /**< Deauths (or disassocs) from one pair in one window that alert. */
#define WW_BEACON_WINDOW_MS       2000U   /**< The window new BSSIDs are counted over.                         */
#define WW_BEACON_THRESHOLD       15U     /**< New BSSIDs in one window that make a beacon flood.              */
#define WW_SETTLE_MS              1000U   /**< After a channel change, BSSIDs are learnt but not counted as new. */
#define WW_TSF_WINDOW_MS          10000U  /**< The window a BSSID's backward timestamps are counted over.     */
#define WW_TSF_THRESHOLD          3U      /**< Backward timestamps in one window that mean two transmitters.   */
#define WW_CLEAR_MS               120000U /**< An alert not seen for this long no longer holds the all clear back, and seen again is raised anew. */

/* ---- The tables ---- */

#define WW_PAIR_MAX         8U    /**< Sender and target pairs whose deauth rate is followed.  */
#define WW_BSSID_MAX        64U   /**< Beaconing BSSIDs remembered; the oldest goes first.     */
#define WW_NET_MAX          32U   /**< Network names a scan remembers.                         */
#define WW_NET_BSSID_MAX    4U    /**< BSSIDs remembered per network name.                     */
#define WW_ALERT_MAX        16U   /**< Alerts kept; the oldest goes first.                     */

/* ---- Types ---- */

/** @brief One frame, as the C5 summarised it (the fields of kode_sys_wifi_frame_t). */
typedef struct {
    uint8_t  channel;               /**< The radio's channel when it was heard.             */
    int8_t   rssi;                  /**< dBm.                                               */
    uint8_t  fc[WW_FC_LEN];         /**< Frame control, as on the air.                      */
    uint8_t  addr1[WW_ADDR_LEN];    /**< Address 1: the receiver.                           */
    uint8_t  addr2[WW_ADDR_LEN];    /**< Address 2: the transmitter; zeros when none.       */
    uint16_t len;                   /**< The frame's length on the air.                     */
    uint8_t  head[WW_HEAD_LEN];     /**< The first bytes after the MAC header; zeros past the end. */
} ww_frame_t;

/** @brief What an alert is about. */
typedef enum {
    WW_ALERT_DEAUTH_FLOOD = 0,   /**< Deauthentications from one sender to one target, above the rate. */
    WW_ALERT_DISASSOC_FLOOD,     /**< Disassociations, the same.                                       */
    WW_ALERT_BEACON_FLOOD,       /**< Many new BSSIDs beaconing in a short window.                     */
    WW_ALERT_BSSID_CLONE,        /**< One BSSID beaconing from two transmitters (its timestamps go back). */
    WW_ALERT_TWIN_SECURITY,      /**< One network name both open and secured.                          */
    WW_ALERT_TWIN_NEW_BSSID,     /**< A known network name on a BSSID that was not there before.       */
    WW_ALERT_KIND_COUNT          /**< One past the last kind.                                          */
} ww_alert_kind_t;

/** @brief How much an alert matters. */
typedef enum {
    WW_SEV_WARN = 0,   /**< Worth a look: often harmless (a new mesh node).  */
    WW_SEV_ALERT       /**< An attack's pattern.                             */
} ww_severity_t;

/** @brief One alert. */
typedef struct {
    ww_alert_kind_t kind;                 /**< What it is about.                                   */
    uint8_t  src[WW_ADDR_LEN];            /**< The sender, or the BSSID it is about.               */
    uint8_t  dst[WW_ADDR_LEN];            /**< The target; ff:ff:ff:ff:ff:ff for everyone; zeros when none. */
    char     ssid[WW_SSID_MAX];           /**< The network name; "" when the rule has none.        */
    uint8_t  channel;                     /**< Where it was heard last.                            */
    int8_t   rssi;                        /**< Its strength when heard last, dBm.                  */
    uint16_t count;                       /**< The highest count of a window that alerted.         */
    uint16_t reason;                      /**< A deauth's or disassoc's reason code; 0 when none or encrypted. */
    bool     protected_mgmt;              /**< The frames were protected (802.11w), so the reason is hidden. */
    uint32_t first_ms;                    /**< When it was raised.                                 */
    uint32_t last_ms;                     /**< When it was seen last.                              */
} ww_alert_t;

/** @brief A deauth or disassoc rate, followed per sender and target. */
typedef struct {
    bool     used;                  /**< The slot holds a pair.                 */
    uint8_t  subtype;               /**< WW_SUBTYPE_DEAUTH or _DISASSOC.        */
    uint8_t  src[WW_ADDR_LEN];      /**< The sender.                            */
    uint8_t  dst[WW_ADDR_LEN];      /**< The target.                            */
    uint32_t window_ms;             /**< When the current window began.         */
    uint32_t last_ms;               /**< When it was heard last.                */
    uint16_t count;                 /**< Frames in the current window.          */
} ww_pair_t;

/** @brief One beaconing BSSID. */
typedef struct {
    bool     used;                  /**< The slot holds a BSSID.                         */
    uint8_t  bssid[WW_ADDR_LEN];    /**< The BSSID (address 2 of its beacons).           */
    uint64_t tsf;                   /**< The newest timestamp it beaconed, microseconds. */
    uint32_t last_ms;               /**< When it was heard last.                         */
    uint32_t back_ms;               /**< When its current backward window began.         */
    uint8_t  back;                  /**< Backward timestamps in that window.             */
} ww_bssid_t;

/** @brief One network name a scan found, and the BSSIDs it was on. */
typedef struct {
    bool     used;                                  /**< The slot holds a network.                       */
    bool     baseline;                              /**< It was in a scan that completed before.         */
    char     ssid[WW_SSID_MAX];                     /**< Its name.                                       */
    uint8_t  n;                                     /**< BSSIDs remembered.                              */
    uint8_t  bssid[WW_NET_BSSID_MAX][WW_ADDR_LEN];  /**< Each BSSID.                                      */
    bool     open[WW_NET_BSSID_MAX];                /**< Whether that BSSID was open.                     */
} ww_net_t;

/** @brief The counts the screen shows. */
typedef struct {
    uint32_t frames;     /**< Frames handed over since the start.     */
    uint32_t mgmt;       /**< Of those, management frames.            */
    uint32_t data;       /**< Of those, data frames.                  */
    uint32_t beacons;    /**< Of the management frames, beacons.      */
    uint32_t deauths;    /**< Deauthentications and disassociations.  */
} ww_counts_t;

/** @brief The whole detector. Zero it with ww_detect_init(). */
typedef struct {
    ww_pair_t   pairs[WW_PAIR_MAX];       /**< The deauth rates followed.            */
    ww_bssid_t  bssids[WW_BSSID_MAX];     /**< The beaconing BSSIDs.                 */
    ww_net_t    nets[WW_NET_MAX];         /**< The networks scans found.             */
    ww_alert_t  alerts[WW_ALERT_MAX];     /**< The alerts, the one seen last at the end. */
    uint8_t     n_alerts;                 /**< Alerts held.                          */
    ww_counts_t counts;                   /**< The counts.                           */
    uint8_t     channel;                  /**< The channel last set.                 */
    uint32_t    channel_ms;               /**< When it was set.                      */
    uint32_t    new_window_ms;            /**< When the new-BSSID window began.      */
    uint16_t    new_count;                /**< New BSSIDs in that window.            */
    bool        scanned;                  /**< A scan has completed: the baseline exists. */
} ww_detect_t;

/* ---- Frame parsing ---- */

/**
 * @brief A frame's type, from its frame control.
 * @param fc The frame control, as on the air.
 * @return WW_TYPE_MGMT, WW_TYPE_CTRL, WW_TYPE_DATA, or 3 for an extension frame.
 */
uint8_t ww_frame_type(const uint8_t fc[WW_FC_LEN]);

/**
 * @brief A frame's subtype, from its frame control.
 * @param fc The frame control, as on the air.
 * @return 0 to 15.
 */
uint8_t ww_frame_subtype(const uint8_t fc[WW_FC_LEN]);

/**
 * @brief A beacon's or probe response's timestamp, the first field of its body.
 * @param head The first bytes after the MAC header.
 * @return The timestamp, microseconds, little-endian on the air.
 */
uint64_t ww_frame_tsf(const uint8_t head[WW_HEAD_LEN]);

/**
 * @brief A deauthentication's or disassociation's reason code, the first field of its body.
 * @param head The first bytes after the MAC header.
 * @return The reason code, little-endian on the air.
 */
uint16_t ww_frame_reason(const uint8_t head[WW_HEAD_LEN]);

/**
 * @brief Whether an address is the broadcast address.
 * @param mac The address.
 * @return true for ff:ff:ff:ff:ff:ff.
 */
bool ww_mac_is_broadcast(const uint8_t mac[WW_ADDR_LEN]);

/**
 * @brief Write an address as "aa:bb:cc:dd:ee:ff".
 * @param mac The address.
 * @param out Receives the text and its NUL; at least WW_MAC_STR_LEN bytes.
 */
void ww_mac_format(const uint8_t mac[WW_ADDR_LEN], char out[WW_MAC_STR_LEN]);

/* ---- The detector ---- */

/**
 * @brief Forget everything: no alerts, no counts, no baseline.
 * @param d The detector.
 */
void ww_detect_init(ww_detect_t *d);

/**
 * @brief Say the radio now listens on another channel.
 *
 * The new-BSSID count starts again, and for WW_SETTLE_MS the BSSIDs heard
 * are learnt without counting as new: every channel has its own networks.
 *
 * @param d       The detector.
 * @param channel The channel.
 * @param now_ms  The time.
 */
void ww_detect_channel(ww_detect_t *d, uint8_t channel, uint32_t now_ms);

/**
 * @brief Take one frame.
 * @param d      The detector.
 * @param f      The frame.
 * @param now_ms The time.
 * @return true when it raised an alert: a new one, or one quiet for WW_CLEAR_MS.
 */
bool ww_detect_frame(ww_detect_t *d, const ww_frame_t *f, uint32_t now_ms);

/**
 * @brief Take one network of a scan.
 * @param d       The detector.
 * @param ssid    Its name, NUL-terminated; "" for a hidden one, which is ignored.
 * @param bssid   Its BSSID.
 * @param channel Its channel.
 * @param open    It has no password.
 * @param rssi    Its strength, dBm.
 * @param now_ms  The time.
 * @return true when it raised an alert, as ww_detect_frame().
 */
bool ww_detect_scan_entry(ww_detect_t *d, const char *ssid, const uint8_t bssid[WW_ADDR_LEN],
                          uint8_t channel, bool open, int8_t rssi, uint32_t now_ms);

/**
 * @brief Say a scan completed: the networks it found become the baseline.
 * @param d The detector.
 */
void ww_detect_scan_done(ww_detect_t *d);

/**
 * @brief Alerts held.
 * @param d The detector.
 * @return 0 to WW_ALERT_MAX.
 */
uint8_t ww_detect_alert_count(const ww_detect_t *d);

/**
 * @brief One alert, the one seen last first.
 * @param d The detector.
 * @param i 0 for the newest, up to ww_detect_alert_count() - 1.
 * @return The alert, or NULL past the end.
 */
const ww_alert_t *ww_detect_alert(const ww_detect_t *d, uint8_t i);

/**
 * @brief Alerts seen within WW_CLEAR_MS: 0 is the all clear.
 * @param d      The detector.
 * @param now_ms The time.
 * @return The count.
 */
uint8_t ww_detect_active(const ww_detect_t *d, uint32_t now_ms);

/**
 * @brief The most serious alert seen within WW_CLEAR_MS.
 * @param d      The detector.
 * @param now_ms The time.
 * @param out    Receives its severity when there is one.
 * @return false when all is clear.
 */
bool ww_detect_worst(const ww_detect_t *d, uint32_t now_ms, ww_severity_t *out);

/**
 * @brief How much a kind of alert matters.
 * @param kind The kind.
 * @return Its severity.
 */
ww_severity_t ww_alert_severity(ww_alert_kind_t kind);

/**
 * @brief A kind's name for the screen, short and in English.
 * @param kind The kind.
 * @return The name; never NULL.
 */
const char *ww_alert_name(ww_alert_kind_t kind);

/**
 * @brief The counts.
 * @param d The detector.
 * @return Them.
 */
const ww_counts_t *ww_detect_counts(const ww_detect_t *d);

/**
 * @brief Forget the alerts, and keep what was learnt (BSSIDs, networks, counts).
 * @param d The detector.
 */
void ww_detect_clear_alerts(ww_detect_t *d);

#ifdef __cplusplus
}
#endif

#endif /* WW_DETECT_H_ */
