# Based on https://github.com/llvm/llvm-project/blob/llvmorg-11.1.0/compiler-rt/lib/fuzzer/build.sh
cc_library(
    name = "libFuzzer",
    srcs = glob([
        "*.cpp",
    ]),
    hdrs = glob([
        "*.h",
        "*.def",
    ]),
    copts = select({
        "@platforms//os:windows": [
            "/Ox", # Optimize for speed.
            "/Oy-", # Do not omit frame pointer.
            "/std:c++17",
        ],
        "//conditions:default": [
            "-g",
            "-O2",
            "-fno-omit-frame-pointer",
            "-std=c++11",
        ],
    }),
    alwayslink = True,
    linkstatic = True,
    visibility = ["//visibility:public"],
)
