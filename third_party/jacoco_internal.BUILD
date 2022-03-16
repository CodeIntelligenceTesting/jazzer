java_library(
    name = "jacoco_internal",
    srcs = glob([
        "org.jacoco.core/src/org/jacoco/core/**/*.java",
    ]),
    resources = glob([
        "org.jacoco.core/src/org/jacoco/core/**/*.properties",
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

java_binary(
    name = "jacoco_cli",
    srcs = glob([
        "org.jacoco.cli/src/org/jacoco/cli/**/*.java",
        "org.jacoco.report/src/org/jacoco/report/**/*.java",
    ]),
    resources = glob([
        "org.jacoco.report/src/org/jacoco/report/**/*.css",
        "org.jacoco.report/src/org/jacoco/report/**/*.gif",
        "org.jacoco.report/src/org/jacoco/report/**/*.js",
    ]),
    main_class = "org.jacoco.cli.internal.Main",
    deps = [
        "//:jacoco_internal",
        "@org_kohsuke_args4j_args4j//jar",
        "@org_ow2_asm_asm//jar",
        "@org_ow2_asm_asm_commons//jar",
        "@org_ow2_asm_asm_tree//jar",
    ],
    visibility = ["//visibility:public"],
)
