load("@rules_foreign_cc//tools/build_defs:cmake.bzl", "cmake_external")
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

cmake_external(
    name = "libjpeg_turbo",
    cache_entries = {
        "CMAKE_BUILD_TYPE": "Release",
        "CMAKE_C_COMPILER": "clang",
        "CMAKE_C_FLAGS": "-fsanitize=address,fuzzer-no-link",
        "CMAKE_SHARED_LINKER_FLAGS": "-fsanitize=address,fuzzer-no-link",
        "WITH_JAVA": "1",
    },
    lib_source = ":all_files",
    shared_libraries = [
        "libjpeg.so",
        "libturbojpeg.so",
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
