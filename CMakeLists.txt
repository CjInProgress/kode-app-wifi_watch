cmake_minimum_required(VERSION 3.22)

# ---- The chip, which is the one board fact spelled out here ---------------
#
# Everything else about the Kode Dot arrives in kbsp's sdkconfig.board. The
# chip cannot, because it has to be known *before* that file has been fetched:
# ESP-IDF resolves the target from this variable, then from the CMake cache,
# then by guessing from whatever sdkconfig files already exist - and on a clean
# checkout there are none, so it falls back to `esp32`. The bootstrap below
# would then configure an ESP32, cache that, and refuse every later pass.
#
# CONFIG_PARTITION_TABLE_CUSTOM_FILENAME in sdkconfig.defaults is spelled out
# for the same class of reason: both are needed before the shared file they
# would otherwise come from can be resolved.
set(IDF_TARGET esp32p4)

# ---- The board's settings, fetched rather than copied ---------------------
#
# Never write flash, PSRAM or cache facts into this project. kbsp describes
# the board and travels with the SDK; a private copy is how an app once
# declared PSRAM this chip does not have, and the symptom was a hung boot with
# no message.
#
# The awkward part is timing, and it is ESP-IDF's: SDKCONFIG_DEFAULTS is read
# at project() time, and the component manager that fetches kbsp runs *inside*
# project(). So on a clean checkout the file this project wants does not exist
# yet.
#
# So a clean checkout configures twice, and the user sees one build. The first
# configure is a throwaway, run from here in a folder of its own, purely so
# that the manager fetches: managed_components/ is the project's, so what it
# fetches is there for the real configure that follows. Its sdkconfig is kept
# in that folder as well. It was written with ESP-IDF's defaults - no PSRAM,
# 2MB of flash - and in the project it would win from then on, because a
# cached value beats a new default every time.
set(KBSP_BOARD
    "${CMAKE_CURRENT_LIST_DIR}/managed_components/kodediy__kbsp/sdkconfig.board")

if(NOT EXISTS "${KBSP_BOARD}" AND NOT KBSP_FETCH_PASS)
    message(STATUS "Fetching the SDK and the board settings (first build only)")
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -G "${CMAKE_GENERATOR}"
                -S "${CMAKE_CURRENT_LIST_DIR}"
                -B "${CMAKE_BINARY_DIR}/kbsp_fetch"
                -DKBSP_FETCH_PASS=ON
                "-DSDKCONFIG=${CMAKE_BINARY_DIR}/kbsp_fetch/sdkconfig"
        RESULT_VARIABLE KBSP_FETCH_RC)
    file(REMOVE_RECURSE "${CMAKE_BINARY_DIR}/kbsp_fetch")
    if(NOT EXISTS "${KBSP_BOARD}")
        message(FATAL_ERROR
            "The SDK could not be fetched (cmake ended with ${KBSP_FETCH_RC}). "
            "Read the first error above. A refused git fetch means that your "
            "GitHub account does not list your SSH key.")
    endif()
endif()

if(EXISTS "${KBSP_BOARD}")
    set(SDKCONFIG_DEFAULTS
        "${KBSP_BOARD};${CMAKE_CURRENT_LIST_DIR}/sdkconfig.defaults")
else()
    # The throwaway configure, which runs without the board settings.
    set(SDKCONFIG_DEFAULTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.defaults")
endif()

# ---- The app's version -----------------------------------------------------
#
# Explicit rather than left to ESP-IDF's git-describe default, which stamps a
# hash like "0d14d62-dirty" - and the launcher prints whatever is here under
# the name on the pill. Bare, so `-DPROJECT_VER=...` still overrides it.
if(NOT DEFINED PROJECT_VER)
    set(PROJECT_VER "00.00.01")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# The project name is the app's identity on the Dot: the launcher tracks the
# app by it, and the image is build/<name>.bin. Rename it first.
project(wifi_watch)
