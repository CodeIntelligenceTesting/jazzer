cc_library(
    name = "jazzer_slicer",
    srcs = [
        "slicer/bytecode_encoder.cc",
        "slicer/code_ir.cc",
        "slicer/common.cc",
        "slicer/control_flow_graph.cc",
        "slicer/debuginfo_encoder.cc",
        "slicer/dex_bytecode.cc",
        "slicer/dex_format.cc",
        "slicer/dex_ir.cc",
        "slicer/dex_ir_builder.cc",
        "slicer/dex_utf8.cc",
        "slicer/instrumentation.cc",
        "slicer/reader.cc",
        "slicer/tryblocks_encoder.cc",
        "slicer/writer.cc",
    ],
    hdrs = glob(["slicer/export/slicer/*.h"]),
    copts = [
        "-Wall",
        "-Wno-sign-compare",
        "-Wno-unused-parameter",
        "-Wno-shift-count-overflow",
        "-Wno-missing-braces",
    ],
    includes = ["slicer/export"],
    visibility = [
        "//visibility:public",
    ],
)
