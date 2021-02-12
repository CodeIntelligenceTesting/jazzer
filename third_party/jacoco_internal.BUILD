java_library(
    name = "jacoco_internal",
    srcs = glob([
        "org.jacoco.core/src/org/jacoco/core/**/*.java",
    ]),
    javacopts = [
        "-Xep:EqualsHashCode:WARN",
    ],
    deps = [
        "@maven//:org_ow2_asm_asm",
        "@maven//:org_ow2_asm_asm_commons",
        "@maven//:org_ow2_asm_asm_tree",
    ],
    visibility = ["//visibility:public"],
)
