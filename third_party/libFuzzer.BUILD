# Based on https://github.com/llvm/llvm-project/blob/llvmorg-11.1.0/compiler-rt/lib/fuzzer/build.sh
LIB_FUZZER_PATH = "compiler-rt/lib/fuzzer"

cc_library(
    name = "libFuzzer",
    srcs = glob([
        LIB_FUZZER_PATH + "/*.cpp",
    ]),
    hdrs = glob([
        LIB_FUZZER_PATH + "/*.h",
        LIB_FUZZER_PATH + "/*.def",
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
