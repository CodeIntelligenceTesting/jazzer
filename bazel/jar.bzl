#
# Copyright 2024 Code Intelligence GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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
