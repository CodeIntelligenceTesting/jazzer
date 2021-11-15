java_library(
    name = "jacoco_internal",
    srcs = glob([
        "org.jacoco.core/src/org/jacoco/core/**/*.java",
    ]),
    resources = glob([
        "org.jacoco.core/src/org/jacoco/core/internal/flow/java_no_throw_methods_list.dat",
    ]),
    javacopts = [
        "-Xep:EqualsHashCode:OFF",
    ],
    deps = [
        "@jazzer_ow2_asm//:asm",
        "@jazzer_ow2_asm//:asm_commons",
        "@jazzer_ow2_asm//:asm_tree",
    ],
    visibility = ["//visibility:public"],
)
