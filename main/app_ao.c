/* SPDX-License-Identifier: GPL-3.0-or-later */
/**
 * @file app_ao.c
 * @brief Wi-Fi Watch's Active Object: it hears Wi-Fi frames, feeds the detector and draws the screen.
 *
 * Receive only. The app asks AO_Radio for the frames the C5 hears on one
 * channel (kode_sys_wifi_frames()) and, now and then, for a scan
 * (kode_sys_wifi_scan()), which is how it learns the networks' names: a
 * frame's record carries only the first 8 bytes after its MAC header. It
 * never sends a frame of its own. Every decision about an attack is in
 * ww_detect.c, which has no SDK call and is tested on the host.
 */
#include "app_ao.h"

#include <stdio.h>
#include <string.h>

#include "kaos.h"
#include "khal_system.h"
#include "kscreen.h"
#include "kui.h"

#include "ww_detect.h"

#define TAG "app.ao"   /**< This file's log tag. */

/* ---- Timing ---- */

#define APP_DWELL_MS        2500U    /**< Time on each channel while hopping.                         */
#define APP_RETRY_MS        5000U    /**< Before asking again after a refusal (busy, no link).          */
#define APP_UI_MS           1000U    /**< The counters on the glass are redrawn this often.            */
#define APP_SCAN_FIRST_MS   3000U    /**< The first scan, once the radio has had time to come up.      */
#define APP_SCAN_MS         120000U  /**< Between two scans: a sweep takes about 38 s of every channel. */
#define APP_SCAN_BUSY_MS    15000U   /**< Before a scan asked again when the radio was busy.           */

/* ---- The queue ---- */

/* The frames door posts a tick and up to KODE_SNIFF_BATCH_MAX frames every
 * 100 ms, while KQP_FRAMES_MARGIN slots stay free; a scan posts its entries
 * while KODE_SYS_LIST_FREE_SLOTS do. This AO runs below AO_Radio and a render
 * pass holds it for about a frame, so a batch can wait whole behind it. The
 * rest: three timers, the render tick, a button's press and release, a touch
 * sample or two, a repaint, and the answers of the two doors. 48 holds a batch
 * and a half on top of all of it, so the margins are never reached in a
 * normal pass. */
#define APP_QUEUE_LEN       48U      /**< Events this AO's queue holds. */
_Static_assert(APP_QUEUE_LEN >= (KQP_AO_QUEUE_LEN + KODE_SYS_LIST_FREE_SLOTS + KQP_FRAMES_MARGIN),
               "the queue holds a scan's margin, the frames' margin and the rest");

/* ---- The channels ---- */

#define APP_CH_COUNT        22U      /**< Channels the hop visits.                          */
#define APP_CH_FIRST_5GHZ   36U      /**< The lowest 5 GHz channel: below is 2.4 GHz.      */

/* ---- The screen ---- */

#define APP_TITLE_Y         56       /**< The title's top, glass pixels.                    */
#define APP_STATUS_Y        108      /**< The status row's top.                             */
#define APP_LAMP_D          24       /**< The status lamp's diameter.                       */
#define APP_WHERE_Y         160      /**< The line saying where it listens.                 */
#define APP_COUNTS_Y        190      /**< The counters' line.                               */
#define APP_LIST_Y          226      /**< The alert list's top.                             */
#define APP_LIST_H          214      /**< The alert list's height: it ends at y 440.        */
#define APP_HINT_Y          448      /**< The hint's top.                                   */
#define APP_LINE_LEN        64U      /**< Bytes of one line of text built here.             */
#define APP_ROWS_MAX        8U       /**< Alerts listed on the glass, the one seen last first. */
#define APP_MS_PER_S        1000U    /**< Milliseconds in a second.                         */

_Static_assert(APP_ROWS_MAX <= WW_ALERT_MAX, "the glass lists no more than the detector keeps");
_Static_assert(WW_HEAD_LEN == KWIFI_FRAME_HEAD_LEN, "the detector reads the head the SDK carries");
_Static_assert(WW_ADDR_LEN == KWIFI_FRAME_ADDR_LEN, "the detector's addresses are the SDK's");
_Static_assert(WW_FC_LEN == KWIFI_FRAME_FC_LEN, "the detector's frame control is the SDK's");
_Static_assert(WW_SSID_MAX == KODE_SYS_WIFI_SSID_MAX, "a scan's name fits the detector's");

/** @brief The app's own signals: they start at MAX_SIG and are posted, never published. */
enum AppAoSignals
{
    APP_RENDER_SIG = MAX_SIG,   /**< kscreen's render pass, a one-shot.                   */
    APP_HOP_SIG,                /**< Time to move to the next channel, or to ask again.   */
    APP_UI_SIG,                 /**< Time to redraw the counters.                         */
    APP_SCAN_SIG                /**< Time for a scan.                                     */
};

/** @brief The Active Object's own state, private to this file. */
typedef struct {
    QActive      super;        /**< The QP/C base; must stay first.                         */
    kscreen_t    screen;       /**< LVGL on the glass, driven from this AO.                 */
    QTimeEvt     hop_t;        /**< APP_HOP_SIG.                                            */
    QTimeEvt     ui_t;         /**< APP_UI_SIG.                                             */
    QTimeEvt     scan_t;       /**< APP_SCAN_SIG.                                           */
    ww_detect_t *det;          /**< The detector, in PSRAM; NULL when there was no room.    */

    bool         req_out;      /**< A frames request waits for its answer.                  */
    bool         on;           /**< The radio listens for this AO.                          */
    uint8_t      why;          /**< kwifi_frames_why_t of the last answer.                  */
    uint8_t      channel;      /**< The channel the radio said it listens on.               */
    bool         hop;          /**< Hopping; false: fixed on ch_idx's channel.              */
    uint8_t      ch_idx;       /**< Into s_channels.                                        */
    bool         scanning;     /**< A scan waits for its answer.                            */
    bool         wifi_asked;   /**< The user asked for Wi-Fi to be switched on.             */

    uint32_t     sec_frames;   /**< Frames the ticks counted in the current second.         */
    uint32_t     sec_mgmt;     /**< Management frames, the same.                            */
    uint32_t     sec_data;     /**< Data frames, the same.                                  */
    uint32_t     dropped;      /**< This chip's lost frames, from the last tick.            */

    bool         ui_ready;     /**< The widgets exist.                                      */
    lv_obj_t    *lamp;         /**< The status lamp.                                        */
    lv_obj_t    *status;       /**< "All clear" or what is wrong.                           */
    lv_obj_t    *where;        /**< Where it listens, or why it does not.                   */
    lv_obj_t    *counts;       /**< The counters.                                           */
    lv_obj_t    *list;         /**< The alert list.                                         */
    lv_obj_t    *empty;        /**< What the list says with no alert.                       */
    lv_obj_t    *rows[APP_ROWS_MAX]; /**< The alert rows, hidden when unused.               */
} AppAo;

/** @brief The channels the hop visits: 2.4 GHz, then the 5 GHz channels without radar rules. */
static const uint8_t s_channels[APP_CH_COUNT] = {
    1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U, 9U, 10U, 11U, 12U, 13U,
    36U, 40U, 44U, 48U, 149U, 153U, 157U, 161U, 165U
};

static QEvtPtr     s_queue[APP_QUEUE_LEN];                               /**< Its event queue. */
static StackType_t s_stack[KQP_AO_STACK_BYTES / sizeof(StackType_t)];    /**< Its stack, in words. */
static AppAo       s_ao;                                                 /**< The one instance. */

QActive * const AO_App = &s_ao.super;

static QState AppAo_initial(AppAo * const me, void const * const par);
static QState AppAo_running(AppAo * const me, QEvt const * const e);
static QState AppAo_waiting(AppAo * const me, QEvt const * const e);
static QState AppAo_drawing(AppAo * const me, QEvt const * const e);

/* ---- Listening ----------------------------------------------------------- */

/**
 * @brief Ask AO_Radio to listen on the current channel; the answer is WIFI_FRAMES_STATE_SIG.
 * @param me The AO.
 */
static void listen_ask(AppAo * const me)
{
    kode_status_t rc;
    uint8_t const ch = s_channels[me->ch_idx];

    rc = kode_sys_wifi_frames(&me->super, true, ch);
    if ( KODE_OK == rc )
    {
        me->req_out = true;
        if ( NULL != me->det )
        {
            ww_detect_channel(me->det, ch, kode_sys_time_ms());
        }
    }
    else
    {
        KLOG_W(TAG, "frames request not posted (status %d)", (int)rc);
        QTimeEvt_disarm(&me->hop_t);
        QTimeEvt_armX(&me->hop_t, KQP_TICKS_PER_MS(APP_RETRY_MS), 0U);
    }
}

/**
 * @brief AO_Radio's answer to a frames request, or the end of a stream it ended itself.
 * @param me The AO.
 * @param st The answer.
 */
static void listen_answer(AppAo * const me, kode_sys_wifi_frames_state_t const * const st)
{
    uint32_t wait_ms = APP_DWELL_MS;

    me->req_out = false;
    me->on      = st->on;
    me->why     = st->why;
    me->channel = st->channel;
    if ( st->on )
    {
        /* Wi-Fi is on now; a later "off" may be tapped on again. */
        me->wifi_asked = false;
    }

    if ( (!st->on) && ((uint8_t)KWIFI_FRAMES_CHANNEL == st->why) && me->hop )
    {
        /* This channel is not allowed here: on to the next one at once. */
        KLOG_I(TAG, "channel %u refused; skipping it", (unsigned)s_channels[me->ch_idx]);
        wait_ms = 1U;
    }
    else if ( !st->on )
    {
        KLOG_I(TAG, "not listening (why %u)", (unsigned)st->why);
        wait_ms = APP_RETRY_MS;
    }
    else
    {
        /* Listening: stay for one dwell. */
    }
    QTimeEvt_disarm(&me->hop_t);
    QTimeEvt_armX(&me->hop_t, KQP_TICKS_PER_MS(wait_ms), 0U);
}

/**
 * @brief The hop timer: the next channel, or the same one asked again after a refusal.
 * @param me The AO.
 */
static void listen_hop(AppAo * const me)
{
    if ( me->req_out )
    {
        /* The last request is still out: AO_Radio would answer busy. */
        QTimeEvt_armX(&me->hop_t, KQP_TICKS_PER_MS(APP_DWELL_MS), 0U);
    }
    else if ( me->scanning && me->on )
    {
        /* A sweep moves the radio itself; a hop now could be refused under it. */
        QTimeEvt_armX(&me->hop_t, KQP_TICKS_PER_MS(APP_DWELL_MS), 0U);
    }
    else if ( (uint8_t)KWIFI_FRAMES_JOINED == me->why )
    {
        /* Joined, only the network's channel can be heard: listen there and stop hopping. */
        me->hop = false;
        (void)kode_sys_wifi_frames(&me->super, true, 0U);
        me->req_out = true;
        me->why     = (uint8_t)KWIFI_FRAMES_OK;
    }
    else
    {
        /* On from a channel heard, or from one the radio refused. */
        if ( me->hop && (me->on || ((uint8_t)KWIFI_FRAMES_CHANNEL == me->why)) )
        {
            me->ch_idx = (uint8_t)((me->ch_idx + 1U) % APP_CH_COUNT);
        }
        listen_ask(me);
    }
}

/* ---- The scan ------------------------------------------------------------ */

/**
 * @brief Ask for a scan; the networks come as WIFI_SCAN_ENTRY_SIG, then WIFI_SCAN_RSP_SIG.
 * @param me The AO.
 */
static void scan_ask(AppAo * const me)
{
    if ( (!me->scanning) && (KODE_OK == kode_sys_wifi_scan(&me->super)) )
    {
        me->scanning = true;
    }
    else
    {
        QTimeEvt_armX(&me->scan_t, KQP_TICKS_PER_MS(APP_SCAN_BUSY_MS), 0U);
    }
}

/**
 * @brief The end of a scan: its networks are the baseline, and the radio is asked back to its channel.
 * @param me  The AO.
 * @param rsp The answer.
 */
static void scan_answer(AppAo * const me, kode_sys_wifi_scan_answer_t const * const rsp)
{
    uint32_t next_ms = APP_SCAN_MS;

    me->scanning = false;
    if ( (uint8_t)KODE_OK == rsp->rc )
    {
        if ( NULL != me->det )
        {
            ww_detect_scan_done(me->det);
        }
        KLOG_I(TAG, "scan done: %u networks", (unsigned)rsp->seen);
    }
    else
    {
        next_ms = APP_SCAN_BUSY_MS;
    }
    QTimeEvt_armX(&me->scan_t, KQP_TICKS_PER_MS(next_ms), 0U);
    /* A sweep may leave the radio on its last channel: ask for ours again. */
    if ( me->on && (!me->req_out) )
    {
        listen_ask(me);
    }
}

/* ---- What is on the glass ------------------------------------------------ */
/* Only this AO's thread calls lv_*, which is why LVGL needs no lock. */

/**
 * @brief One line of text centred at the top of the glass.
 * @param text The text.
 * @param font Its face.
 * @param col  Its colour.
 * @param y    Its top, glass pixels.
 * @return The label, which LVGL owns.
 */
static lv_obj_t *line_new(const char *text, const lv_font_t *font, lv_color_t col, int32_t y)
{
    lv_obj_t * const label = lv_label_create(lv_screen_active());

    lv_label_set_text(label, text);
    lv_obj_set_style_text_font(label, font, 0);
    lv_obj_set_style_text_color(label, col, 0);
    lv_obj_align(label, LV_ALIGN_TOP_MID, 0, y);
    return label;
}

/**
 * @brief Say where the radio listens, or why it does not.
 * @param me  The AO.
 * @param out Receives the line; APP_LINE_LEN bytes.
 */
static void where_text(AppAo const * const me, char out[APP_LINE_LEN])
{
    const char *mode = "fixed";

    if ( me->hop )
    {
        mode = "hopping";
    }
    if ( me->on )
    {
        const char *band = "2.4 GHz";

        if ( APP_CH_FIRST_5GHZ <= me->channel )
        {
            band = "5 GHz";
        }
        (void)snprintf(out, APP_LINE_LEN, "Channel %u, %s, %s", (unsigned)me->channel, band, mode);
    }
    else if ( me->req_out )
    {
        (void)snprintf(out, APP_LINE_LEN, "Asking the radio to listen...");
    }
    else
    {
        const char *why = "Not listening";

        switch ( me->why )
        {
            case (uint8_t)KWIFI_FRAMES_WIFI_OFF:
                why = "Wi-Fi is off: tap to turn it on";
                break;
            case (uint8_t)KWIFI_FRAMES_NO_LINK:
                why = "No link to the radio yet";
                break;
            case (uint8_t)KWIFI_FRAMES_NO_SERVICE:
                why = "This radio firmware cannot listen";
                break;
            case (uint8_t)KWIFI_FRAMES_BUSY:
                why = "The radio is busy; trying again";
                break;
            case (uint8_t)KWIFI_FRAMES_MEMORY:
                why = "The radio has no room to listen";
                break;
            case (uint8_t)KWIFI_FRAMES_CHANNEL:
                why = "That channel is not allowed here";
                break;
            case (uint8_t)KWIFI_FRAMES_RESTING:
                why = "Resting";
                break;
            default:
                break;
        }
        (void)snprintf(out, APP_LINE_LEN, "%s", why);
    }
}

/**
 * @brief Fill one alert row: its kind on the first line, who and where under it.
 * @param row The pill.
 * @param a   The alert.
 */
static void row_fill(lv_obj_t *row, ww_alert_t const * const a)
{
    lv_obj_t * const name = lv_obj_get_child_by_name(row, "name");
    lv_obj_t * const sub  = lv_obj_get_child_by_name(row, "sub");
    lv_obj_t * const slot = lv_obj_get_child_by_name(row, "slot");
    char             mac[WW_MAC_STR_LEN];
    char             dst[WW_MAC_STR_LEN];
    char             line[APP_LINE_LEN];

    ww_mac_format(a->src, mac);
    if ( ww_mac_is_broadcast(a->dst) )
    {
        (void)snprintf(dst, sizeof(dst), "everyone");
    }
    else
    {
        ww_mac_format(a->dst, dst);
    }

    switch ( a->kind )
    {
        case WW_ALERT_DEAUTH_FLOOD:
        case WW_ALERT_DISASSOC_FLOOD:
            (void)snprintf(line, sizeof(line), "%s > %s, %u/s, ch %u", mac, dst,
                           (unsigned)a->count, (unsigned)a->channel);
            break;
        case WW_ALERT_BEACON_FLOOD:
            (void)snprintf(line, sizeof(line), "%u new BSSIDs in 2 s, ch %u",
                           (unsigned)a->count, (unsigned)a->channel);
            break;
        case WW_ALERT_BSSID_CLONE:
            (void)snprintf(line, sizeof(line), "%s, 2 clocks, ch %u", mac, (unsigned)a->channel);
            break;
        default:
            (void)snprintf(line, sizeof(line), "\"%s\" on %s, ch %u", a->ssid, mac,
                           (unsigned)a->channel);
            break;
    }
    if ( NULL != name )
    {
        lv_label_set_text(name, ww_alert_name(a->kind));
    }
    if ( NULL != sub )
    {
        lv_label_set_text(sub, line);
    }
    if ( NULL != slot )
    {
        lv_color_t col = KUI_COLOR_DANGER;

        if ( WW_SEV_WARN == ww_alert_severity(a->kind) )
        {
            col = KUI_COLOR_WARN;
        }
        lv_obj_set_style_bg_color(slot, col, 0);
    }
}

/**
 * @brief Redraw the status, the counters and the list from the detector.
 * @param me The AO.
 */
static void ui_refresh(AppAo * const me)
{
    char          line[APP_LINE_LEN];
    uint32_t const now = kode_sys_time_ms();
    ww_severity_t sev  = WW_SEV_WARN;
    uint8_t       n    = 0U;
    uint8_t       i;

    if ( !me->ui_ready )
    {
        return;
    }

    if ( NULL == me->det )
    {
        lv_label_set_text(me->status, "No memory");
        kui_lamp_set(me->lamp, KUI_COLOR_DANGER, true);
        return;
    }

    if ( ww_detect_worst(me->det, now, &sev) )
    {
        uint8_t const active = ww_detect_active(me->det, now);
        const char   *plural = "s";

        if ( WW_SEV_ALERT == sev )
        {
            kui_lamp_set(me->lamp, KUI_COLOR_DANGER, true);
        }
        else
        {
            kui_lamp_set(me->lamp, KUI_COLOR_WARN, true);
        }
        if ( 1U == active )
        {
            plural = "";
        }
        (void)snprintf(line, sizeof(line), "%u alert%s", (unsigned)active, plural);
        lv_label_set_text(me->status, line);
    }
    else if ( me->on )
    {
        kui_lamp_set(me->lamp, KUI_COLOR_OK, true);
        lv_label_set_text(me->status, "All clear");
    }
    else
    {
        kui_lamp_set(me->lamp, KUI_COLOR_OK, false);
        lv_label_set_text(me->status, "Not listening");
    }

    where_text(me, line);
    lv_label_set_text(me->where, line);

    if ( 0U < me->dropped )
    {
        (void)snprintf(line, sizeof(line), "%lu frames/s   mgmt %lu   data %lu   lost %lu",
                       (unsigned long)me->sec_frames, (unsigned long)me->sec_mgmt,
                       (unsigned long)me->sec_data, (unsigned long)me->dropped);
    }
    else
    {
        (void)snprintf(line, sizeof(line), "%lu frames/s   mgmt %lu   data %lu",
                       (unsigned long)me->sec_frames, (unsigned long)me->sec_mgmt,
                       (unsigned long)me->sec_data);
    }
    lv_label_set_text(me->counts, line);

    n = ww_detect_alert_count(me->det);
    if ( APP_ROWS_MAX < n )
    {
        n = (uint8_t)APP_ROWS_MAX;
    }
    for ( i = 0U; APP_ROWS_MAX > i; i++ )
    {
        if ( i < n )
        {
            row_fill(me->rows[i], ww_detect_alert(me->det, i));
            lv_obj_set_hidden(me->rows[i], false);
        }
        else
        {
            lv_obj_set_hidden(me->rows[i], true);
        }
    }
    if ( 0U == n )
    {
        lv_obj_set_hidden(me->empty, false);
    }
    else
    {
        lv_obj_set_hidden(me->empty, true);
    }
}

/**
 * @brief A tap on the glass: when Wi-Fi is off, the one thing a tap does is turn it on.
 *
 * The listen needs the C5's station started. Turning it on is the user's
 * choice, so it waits for this tap, and it is remembered as kodeOS's own
 * Wi-Fi switch is.
 *
 * @param e The click; its user data is the AO.
 */
static void tap_cb(lv_event_t *e)
{
    AppAo * const me = (AppAo *)lv_event_get_user_data(e);

    if ( (!me->on) && ((uint8_t)KWIFI_FRAMES_WIFI_OFF == me->why) && (!me->wifi_asked) )
    {
        KLOG_I(TAG, "turning Wi-Fi on, as asked");
        wifi_start_request();
        me->wifi_asked = true;
        QTimeEvt_disarm(&me->hop_t);
        QTimeEvt_armX(&me->hop_t, KQP_TICKS_PER_MS(APP_RETRY_MS), 0U);
    }
}

/**
 * @brief Build the screen. Nothing here draws: the next render pass does.
 * @param me The AO.
 */
static void ui_build(AppAo * const me)
{
    lv_obj_t * const scr = lv_screen_active();
    lv_obj_t        *row;
    uint8_t          i;

    lv_obj_add_style(scr, &kui_style_screen, 0);
    lv_obj_add_event_cb(scr, &tap_cb, LV_EVENT_CLICKED, me);

    (void)line_new("Wi-Fi Watch", &kui_font_heading, KUI_COLOR_TEXT_ON_BG, APP_TITLE_Y);

    row = kui_flex_create(scr, LV_FLEX_FLOW_ROW, KUI_SPACE_LG, 0U, LV_FLEX_ALIGN_CENTER,
                          LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_align(row, LV_ALIGN_TOP_MID, 0, APP_STATUS_Y);
    lv_obj_set_clickable(row, false);
    me->lamp   = kui_lamp_create(row, APP_LAMP_D);
    me->status = lv_label_create(row);
    lv_obj_set_style_text_font(me->status, &kui_font_title, 0);
    lv_obj_set_style_text_color(me->status, KUI_COLOR_TEXT_ON_BG, 0);
    lv_label_set_text(me->status, "Starting");

    me->where  = line_new("", &kui_font_caption, KUI_COLOR_TEXT_MUTED, APP_WHERE_Y);
    me->counts = line_new("", &kui_font_caption, KUI_COLOR_TEXT_MUTED, APP_COUNTS_Y);

    me->list = kui_flex_create(scr, LV_FLEX_FLOW_COLUMN, KUI_SPACE_LG, 0U, LV_FLEX_ALIGN_START,
                               LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_START);
    lv_obj_set_size(me->list, KUI_PILL_W, APP_LIST_H);
    lv_obj_align(me->list, LV_ALIGN_TOP_MID, 0, APP_LIST_Y);
    lv_obj_set_scrollable(me->list, true);

    me->empty = lv_label_create(me->list);
    lv_obj_set_style_text_font(me->empty, &kui_font_caption, 0);
    lv_obj_set_style_text_color(me->empty, KUI_COLOR_TEXT_MUTED, 0);
    lv_label_set_text(me->empty, "No alerts. Receive only: nothing is sent.");

    for ( i = 0U; APP_ROWS_MAX > i; i++ )
    {
        me->rows[i] = kui_pill_create(me->list, "", "");
        lv_obj_set_hidden(me->rows[i], true);
    }

    (void)line_new("TOP: hop / fix   UP DOWN: channel", &kui_font_caption, KUI_COLOR_TEXT_MUTED,
                   APP_HINT_Y);
    me->ui_ready = true;
    ui_refresh(me);
}

/* ---- The buttons --------------------------------------------------------- */

/**
 * @brief TOP toggles hopping; UP and DOWN fix the radio on the next or the previous channel.
 * @param me The AO.
 * @param id KODE_SYS_BUTTON_*.
 * @return true when the button was this AO's.
 */
static bool button_press(AppAo * const me, uint32_t id)
{
    bool mine = true;

    if ( KODE_SYS_BUTTON_TOP == id )
    {
        me->hop = !me->hop;
    }
    else if ( KODE_SYS_BUTTON_UP == id )
    {
        me->hop    = false;
        me->ch_idx = (uint8_t)((me->ch_idx + 1U) % APP_CH_COUNT);
    }
    else if ( KODE_SYS_BUTTON_DOWN == id )
    {
        me->hop    = false;
        me->ch_idx = (uint8_t)((me->ch_idx + APP_CH_COUNT - 1U) % APP_CH_COUNT);
    }
    else
    {
        mine = false;
    }
    if ( mine && (!me->req_out) && ((KODE_SYS_BUTTON_TOP != id) || (!me->on)) )
    {
        /* A new channel is asked for now; toggling hop on just lets the next dwell move. */
        listen_ask(me);
    }
    if ( mine )
    {
        ui_refresh(me);
    }
    return mine;
}

/* ---- The AO -------------------------------------------------------------- */

void AppAo_ctor(void)
{
    AppAo * const me = &s_ao;

    (void)memset(me, 0, sizeof(*me));
    QActive_ctor(&me->super, Q_STATE_CAST(&AppAo_initial));
    kscreen_ctor(&me->screen, &me->super, (enum_t)APP_RENDER_SIG);
    QTimeEvt_ctorX(&me->hop_t, &me->super, (enum_t)APP_HOP_SIG, 0U);
    QTimeEvt_ctorX(&me->ui_t, &me->super, (enum_t)APP_UI_SIG, 0U);
    QTimeEvt_ctorX(&me->scan_t, &me->super, (enum_t)APP_SCAN_SIG, 0U);
    me->hop = true;
    me->why = (uint8_t)KWIFI_FRAMES_OK;

    /* About 5.5 KB of tables: PSRAM, where a buffer belongs (ram_budget.txt). */
    me->det = (ww_detect_t *)khal_alloc_psram(sizeof(uint64_t), sizeof(ww_detect_t));
    if ( NULL == me->det )
    {
        KLOG_E(TAG, "no PSRAM for the detector");
    }
    else
    {
        ww_detect_init(me->det);
    }
}

void AppAo_start(void)
{
    /* A named task: an assert then names it instead of "AO". */
    QActive_setAttr(AO_App, TASK_NAME_ATTR, "wifi_watch");
    /* The level the SDK keeps for a renderer: rendering is heavy and the least urgent. */
    QACTIVE_START(AO_App, KODE_PRIO_USER_GUI, s_queue, Q_DIM(s_queue),
                  s_stack, sizeof(s_stack), (void *)0);
}

/**
 * @brief The initial transition: subscribe, then ask the panel and the radio.
 * @param me  The AO.
 * @param par Unused.
 * @return The transition to AppAo_waiting.
 */
static QState AppAo_initial(AppAo * const me, void const * const par)
{
    (void)par;

    QActive_subscribe(&me->super, BUTTON_EVT_SIG);
    kscreen_start(&me->screen);

    /* The frames and scan answers are posted to this AO, never published: nothing to subscribe. */
    listen_ask(me);
    QTimeEvt_armX(&me->scan_t, KQP_TICKS_PER_MS(APP_SCAN_FIRST_MS), 0U);
    QTimeEvt_armX(&me->ui_t, KQP_TICKS_PER_MS(APP_UI_MS), 0U);
    KLOG_I(TAG, "up; receive only");
    return Q_TRAN(&AppAo_waiting);
}

/**
 * @brief The parent of both states: the radio, the detector and the timers, with or without a picture.
 * @param me The AO.
 * @param e  The event.
 * @return Q_HANDLED() for what it handles, Q_SUPER() otherwise.
 */
static QState AppAo_running(AppAo * const me, QEvt const * const e)
{
    QState status = Q_HANDLED();

    switch ( e->sig )
    {
        case WIFI_FRAME_SIG:
        {
            kode_sys_wifi_frame_t const * const fe = Q_EVT_CAST(kode_sys_wifi_frame_t);
            ww_frame_t f;

            if ( NULL != me->det )
            {
                f.channel = fe->channel;
                f.rssi    = fe->rssi;
                f.len     = fe->len;
                (void)memcpy(f.fc, fe->fc, sizeof(f.fc));
                (void)memcpy(f.addr1, fe->addr1, sizeof(f.addr1));
                (void)memcpy(f.addr2, fe->addr2, sizeof(f.addr2));
                (void)memcpy(f.head, fe->head, sizeof(f.head));
                if ( ww_detect_frame(me->det, &f, kode_sys_time_ms()) )
                {
                    KLOG_W(TAG, "alert: %s", ww_alert_name(ww_detect_alert(me->det, 0U)->kind));
                    ui_refresh(me);
                }
            }
            break;
        }
        case WIFI_FRAMES_TICK_SIG:
        {
            kode_sys_wifi_frames_tick_t const * const t = Q_EVT_CAST(kode_sys_wifi_frames_tick_t);

            me->sec_mgmt  += t->mgmt;
            me->sec_data  += t->data;
            me->sec_frames = me->sec_mgmt + me->sec_data;
            me->dropped    = t->dropped;
            me->channel    = t->channel;
            break;
        }
        case WIFI_FRAMES_STATE_SIG:
        {
            listen_answer(me, Q_EVT_CAST(kode_sys_wifi_frames_state_t));
            ui_refresh(me);
            break;
        }
        case WIFI_SCAN_ENTRY_SIG:
        {
            kode_sys_wifi_scan_entry_t const * const se = Q_EVT_CAST(kode_sys_wifi_scan_entry_t);
            char ssid[WW_SSID_MAX];

            if ( NULL != me->det )
            {
                /* A copy that is terminated whatever arrived. */
                (void)memcpy(ssid, se->ssid, sizeof(ssid));
                ssid[WW_SSID_MAX - 1U] = '\0';
                if ( ww_detect_scan_entry(me->det, ssid, se->bssid, se->channel, 0U == se->authmode,
                                          se->rssi, kode_sys_time_ms()) )
                {
                    KLOG_W(TAG, "alert: %s", ww_alert_name(ww_detect_alert(me->det, 0U)->kind));
                    ui_refresh(me);
                }
            }
            break;
        }
        case WIFI_SCAN_RSP_SIG:
        {
            scan_answer(me, Q_EVT_CAST(kode_sys_wifi_scan_answer_t));
            break;
        }
        case APP_HOP_SIG:
        {
            listen_hop(me);
            break;
        }
        case APP_SCAN_SIG:
        {
            scan_ask(me);
            break;
        }
        case APP_UI_SIG:
        {
            ui_refresh(me);
            me->sec_frames = 0U;
            me->sec_mgmt   = 0U;
            me->sec_data   = 0U;
            QTimeEvt_armX(&me->ui_t, KQP_TICKS_PER_MS(APP_UI_MS), 0U);
            break;
        }
        default:
        {
            status = Q_SUPER(&QHsm_top);
            break;
        }
    }
    return status;
}

/**
 * @brief Waiting for AO_Display's answer: LVGL is not started yet, the radio already listens.
 * @param me The AO.
 * @param e  The event.
 * @return Q_HANDLED(), a transition to AppAo_drawing, or Q_SUPER().
 */
static QState AppAo_waiting(AppAo * const me, QEvt const * const e)
{
    QState status;

    switch ( e->sig )
    {
        case DISPLAY_STATE_SIG:
        {
            if ( KODE_OK == kscreen_open(&me->screen, Q_EVT_CAST(DisplayStateEvt)) )
            {
                status = Q_TRAN(&AppAo_drawing);
            }
            else
            {
                /* kscreen has said why; the detector goes on, and the log shows its alerts. */
                status = Q_HANDLED();
            }
            break;
        }
        default:
        {
            status = Q_SUPER(&AppAo_running);
            break;
        }
    }
    return status;
}

/**
 * @brief Drawing: the screen is built and the render pass ticks.
 * @param me The AO.
 * @param e  The event.
 * @return Q_HANDLED() for what it handles, Q_SUPER() otherwise.
 */
static QState AppAo_drawing(AppAo * const me, QEvt const * const e)
{
    QState status = Q_HANDLED();

    switch ( e->sig )
    {
        case Q_ENTRY_SIG:
        {
            ui_build(me);
            break;
        }
        /* Always to kscreen_tick(), which re-arms the one-shot: a periodic tick
         * would fill the queue behind a slow frame. */
        case APP_RENDER_SIG:
        {
            kscreen_tick(&me->screen);
            break;
        }
        case TOUCH_EVT_SIG:
        {
            kscreen_touch(&me->screen, Q_EVT_CAST(TouchEvt));
            break;
        }
        case DISPLAY_REPAINT_SIG:
        {
            kscreen_repaint(&me->screen);
            break;
        }
        case BUTTON_EVT_SIG:
        {
            ButtonEvt const * const be = Q_EVT_CAST(ButtonEvt);

            /* BOT is kodeOS's: holding it goes home (rule D8). */
            if ( !(be->pressed && button_press(me, (uint32_t)be->id)) )
            {
                status = Q_SUPER(&AppAo_running);
            }
            break;
        }
        default:
        {
            status = Q_SUPER(&AppAo_running);
            break;
        }
    }
    return status;
}
