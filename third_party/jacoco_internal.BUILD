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
        "@org_ow2_asm_asm//jar",
        "@org_ow2_asm_asm_commons//jar",
        "@org_ow2_asm_asm_tree//jar",
    ],
    visibility = ["//visibility:public"],
)
