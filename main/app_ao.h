/* SPDX-License-Identifier: GPL-3.0-or-later */
/**
 * @file app_ao.h
 * @brief Wi-Fi Watch's Active Object: it hears Wi-Fi frames, feeds the detector and draws the screen.
 */
#ifndef APP_AO_H_
#define APP_AO_H_

#include "kode_sys.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- The Active Object ---- */

extern QActive * const AO_App;   /**< The one instance, opaque outside app_ao.c. */

/* ---- Calls ---- */

/**
 * @brief Construct the Active Object; call it after kode_init() and before AppAo_start().
 */
void AppAo_ctor(void);

/**
 * @brief Give the Active Object its task, queue and stack, and start it.
 */
void AppAo_start(void);

#ifdef __cplusplus
}
#endif

#endif /* APP_AO_H_ */
