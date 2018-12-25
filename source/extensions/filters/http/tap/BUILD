licenses(["notice"])  # Apache 2

# FIXFIX

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

envoy_cc_library(
    name = "tap_filter_lib",
    srcs = ["tap_filter.cc"],
    hdrs = ["tap_filter.h"],
    deps = [
        "//include/envoy/http:filter_interface",
        "//include/envoy/server:admin_interface",
        "//include/envoy/singleton:manager_interface",
        "//include/envoy/thread_local:thread_local_interface",
        "@envoy_api//envoy/admin/v2alpha:tap_cc",
        "@envoy_api//envoy/config/filter/http/tap/v2alpha:tap_cc",
    ],
)

envoy_cc_library(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        ":tap_filter_lib",
        "//include/envoy/registry",
        "//source/extensions/filters/http:well_known_names",
        "//source/extensions/filters/http/common:factory_base_lib",
        "@envoy_api//envoy/config/filter/http/tap/v2alpha:tap_cc",
    ],
)
