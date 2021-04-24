java_library(
    name = "asm",
    srcs = glob(["asm/src/main/**/*.java"]),
    visibility = ["//visibility:public"],
)

java_library(
    name = "asm_commons",
    srcs = glob(["asm-commons/src/main/**/*.java"]),
    deps = [
        ":asm",
        ":asm_analysis",
        ":asm_tree",
    ],
    visibility = ["//visibility:public"],
)

java_library(
    name = "asm_tree",
    srcs = glob(["asm-tree/src/main/**/*.java"]),
    deps = [":asm"],
    visibility = ["//visibility:public"],
)

java_library(
    name = "asm_analysis",
    srcs = glob(["asm-analysis/src/main/**/*.java"]),
    deps = [
        ":asm",
        ":asm_tree",
    ],
)
