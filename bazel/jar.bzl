#
# Copyright 2024 Code Intelligence GmbH
#
# By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
#
# The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
# located in the root directory of the project.
#

def _strip_jar(ctx):
    out_jar = ctx.outputs.out
    if out_jar == None:
        out_jar = ctx.actions.declare_file(ctx.attr.name + ".jar")

    args = ctx.actions.args()
    args.add(ctx.file.jar)
    args.add(out_jar)
    args.add_all(ctx.attr.paths_to_strip)
    args.add_all(ctx.attr.paths_to_keep, format_each = "+%s")
    ctx.actions.run(
        outputs = [out_jar],
        inputs = [ctx.file.jar],
        arguments = [args],
        executable = ctx.executable._jar_stripper,
    )

    return [
        DefaultInfo(
            files = depset([out_jar]),
        ),
        coverage_common.instrumented_files_info(
            ctx,
            dependency_attributes = ["jar"],
        ),
    ]

strip_jar = rule(
    implementation = _strip_jar,
    attrs = {
        "out": attr.output(),
        "jar": attr.label(
            mandatory = True,
            allow_single_file = [".jar"],
        ),
        "paths_to_strip": attr.string_list(),
        "paths_to_keep": attr.string_list(),
        "_jar_stripper": attr.label(
            default = "//bazel/tools/java:JarStripper",
            cfg = "exec",
            executable = True,
        ),
    },
)
