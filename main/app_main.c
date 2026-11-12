/* SPDX-License-Identifier: GPL-3.0-or-later */
/**
 * @file app_main.c
 * @brief The app's entry point: bring the system up, then start Wi-Fi Watch's Active Object.
 */
#include "kode.h"

#include "app_ao.h"

/* The name on the launcher's pill and up to four categories from the catalog's categories.txt. */
KODE_APP_MANIFEST("Wi-Fi Watch", "wireless,tools");

/**
 * @brief ESP-IDF's entry point.
 */
void app_main(void)
{
    /* First, always: nothing may post to an Active Object before its queue exists. */
    kode_init();

    AppAo_ctor();
    AppAo_start();
}
