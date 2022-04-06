load("@com_github_johnynek_bazel_jar_jar//:jar_jar.bzl", "jar_jar")

java_import(
    name = "jacoco_internal",
    jars = ["jacoco_internal_shaded.jar"],
    deps = [
        "@org_ow2_asm_asm//jar",
        "@org_ow2_asm_asm_commons//jar",
        "@org_ow2_asm_asm_tree//jar",
    ],
    visibility = ["//visibility:public"],
)

jar_jar(
    name = "jacoco_internal_shaded",
    input_jar = "libjacoco_internal_unshaded.jar",
    rules = "@jazzer//third_party:jacoco_internal.jarjar",
)

java_library(
    name = "jacoco_internal_unshaded",
    srcs = glob([
        "org.jacoco.core/src/org/jacoco/core/**/*.java",
    ]),
    resources = glob([
        "org.jacoco.core/src/org/jacoco/core/**/*.properties",
    ]),
    javacopts = [
        "-Xep:EqualsHashCode:OFF",
    ],
    deps = [
        "@org_ow2_asm_asm//jar",
        "@org_ow2_asm_asm_commons//jar",
        "@org_ow2_asm_asm_tree//jar",
    ],
)
