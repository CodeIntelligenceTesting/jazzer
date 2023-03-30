cc_library(
    name = "libfuzzer_no_main",
    srcs = glob(
        [
            "*.cpp",
        ],
        exclude = ["FuzzerMain.cpp"],
    ),
    hdrs = glob([
        "*.h",
        "*.def",
    ]),
    copts = [
        # https://github.com/llvm/llvm-project/blob/eab395fa4074a5a0cbfebe811937dbb1816df9ef/compiler-rt/CMakeLists.txt#L294-L309
        "-fno-builtin",
        "-fno-exceptions",
        "-funwind-tables",
        "-fno-stack-protector",
        "-fvisibility=hidden",
        "-fno-lto",
    ] + select({
        "@platforms//os:windows": [
            # https://github.com/llvm/llvm-project/blob/eab395fa4074a5a0cbfebe811937dbb1816df9ef/compiler-rt/CMakeLists.txt#L362-L363
            "/Oy-",
            "/GS-",
            "/std:c++17",
        ],
        "//conditions:default": [
            # https://github.com/llvm/llvm-project/commit/29d3ba7576b30a37bd19a5d40f304fc39c6ab13d
            "-fno-omit-frame-pointer",
            # https://github.com/llvm/llvm-project/blob/eab395fa4074a5a0cbfebe811937dbb1816df9ef/compiler-rt/CMakeLists.txt#L392
            "-O3",
            # Use the same C++ standard as Jazzer itself.
            "-std=c++17",
        ],
    }),
    linkstatic = True,
    visibility = ["//visibility:public"],
    alwayslink = True,
)
