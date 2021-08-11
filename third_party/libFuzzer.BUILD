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
    copts = [
        "-g",
        "-O2",
        "-fno-omit-frame-pointer",
        "-std=c++11",
    ],
    alwayslink = True,
    linkstatic = True,
    visibility = ["//visibility:public"],
)
