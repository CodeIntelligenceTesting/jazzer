load("@bazel_jar_jar//:jar_jar.bzl", "jar_jar")

java_import(
    name = "jacoco_internal",
    jars = ["jacoco_internal_shaded.jar"],
    visibility = ["//visibility:public"],
    deps = [
        "@maven//:org_ow2_asm_asm",
        "@maven//:org_ow2_asm_asm_commons",
        "@maven//:org_ow2_asm_asm_tree",
    ],
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
    javacopts = [
        "-Xep:EqualsHashCode:OFF",
        "-Xep:ReturnValueIgnored:OFF",
    ],
    resources = glob([
        "org.jacoco.core/src/org/jacoco/core/**/*.properties",
    ]),
    deps = [
        "@maven//:org_ow2_asm_asm",
        "@maven//:org_ow2_asm_asm_commons",
        "@maven//:org_ow2_asm_asm_tree",
    ],
)
