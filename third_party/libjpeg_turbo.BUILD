load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake")
load("@bazel_skylib//rules:copy_file.bzl", "copy_file")
load("@bazel_skylib//rules:select_file.bzl", "select_file")

filegroup(
    name = "all_files",
    srcs = glob(["**"]),
)

filegroup(
    name = "java_files",
    srcs = glob(["java/org/libjpegturbo/turbojpeg/*.java"]),
)

cc_import(
    name = "libawt",
    hdrs = [
        "@local_jdk//:include/jawt.h",
    ],
    shared_library = "@local_jdk//:lib/libawt.so",
)

cmake(
    name = "libjpeg_turbo",
    cache_entries = {
        "WITH_JAVA": "1",
    },
    copts = [
        "-fsanitize=address,fuzzer-no-link",
        "-fPIC",
    ],
    lib_source = ":all_files",
    linkopts = [
        "-fsanitize=address,fuzzer-no-link",
    ],
    out_shared_libs = [
        "libjpeg.so",
        "libturbojpeg.so",
    ],
    deps = [
        ":libawt",
        "@rules_jni//jni",
    ],
)

select_file(
    name = "libturbojpeg_so",
    srcs = ":libjpeg_turbo",
    subpath = "lib/libturbojpeg.so",
)

copy_file(
    name = "turbojpeg_native",
    src = ":libturbojpeg_so",
    out = "libturbojpeg.so",
    visibility = ["//visibility:public"],
)

genrule(
    name = "generate_jni_loader",
    outs = ["TJLoader.java"],
    cmd = "echo 'package org.libjpegturbo.turbojpeg; final class TJLoader { static void load() { System.loadLibrary(\"turbojpeg\"); }}' > $@",
)

java_library(
    name = "turbojpeg_java",
    srcs = [
        ":generate_jni_loader",
        ":java_files",
    ],
    visibility = ["//visibility:public"],
)
