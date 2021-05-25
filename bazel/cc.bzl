# Copyright 2021 Code Intelligence GmbH
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

def _add_cxxopt_std_17_impl(settings, attr):
    return {
        "//command_line_option:cxxopt": settings["//command_line_option:cxxopt"] + ["-std=c++17"],
    }

_add_cxxopt_std_17 = transition(
    implementation = _add_cxxopt_std_17_impl,
    inputs = [
        "//command_line_option:cxxopt",
    ],
    outputs = [
        "//command_line_option:cxxopt",
    ],
)

def _cc_17_binary_impl(ctx):
    output_file = ctx.actions.declare_file(ctx.label.name)

    # Do not include the original target in the runfiles of the target built with the transition.
    all_runfiles = ctx.attr.binary[0][DefaultInfo].default_runfiles.files.to_list()
    filtered_runfiles = ctx.runfiles([runfile for runfile in all_runfiles if runfile != ctx.executable.binary])
    ctx.actions.symlink(
        output = output_file,
        target_file = ctx.executable.binary,
        is_executable = True,
    )
    return [
        DefaultInfo(
            executable = output_file,
            runfiles = filtered_runfiles,
        ),
    ]

_cc_17_binary = rule(
    implementation = _cc_17_binary_impl,
    attrs = {
        "binary": attr.label(
            executable = True,
            cfg = _add_cxxopt_std_17,
            mandatory = True,
            providers = [CcInfo],
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
    executable = True,
)

# A cc_binary that is built with -std=c++17, including all its transitive dependencies.
# This is redundant while developing Jazzer itself as the .bazelrc sets this flag for all build commands, but is needed
# when Jazzer is included as an external workspace.
def cc_17_binary(name, srcs, deps, visibility, **kwargs):
    native.cc_binary(
        name = name + "_original",
        srcs = srcs,
        deps = deps,
        visibility = ["//visibility:private"],
        **kwargs
    )

    _cc_17_binary(
        name = name,
        binary = ":%s_original" % name,
        visibility = visibility,
    )
