# ww_detect.c is the detector: plain C, no SDK call, tested on the host by
# test/run.sh. kscreen brings LVGL and kui with it from idf_component.yml.
idf_component_register(
    SRCS "app_main.c" "app_ao.c" "ww_detect.c"
    INCLUDE_DIRS "."
    REQUIRES kode
    PRIV_REQUIRES kscreen
)
