#!/bin/sh
# The app's pure part, the detector, compiled and run on the host. No ESP-IDF.
#
# The tests are assert()s, so NDEBUG is undone whatever the environment sets.
# WW_CFLAGS adds flags, e.g. -fsanitize=address,undefined.
set -e
cd "$(dirname "$0")"
out="${TMPDIR:-/tmp}/wifi_watch_tests"
mkdir -p "$out"
cc -std=c11 -Wall -Wextra -Werror -Wconversion -UNDEBUG ${WW_CFLAGS:-} -I../main test_detect.c ../main/ww_detect.c -o "$out/detect"
"$out/detect"
