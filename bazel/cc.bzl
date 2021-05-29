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

def _cc_17_library_impl(ctx):
    library = ctx.attr.library[0]
    return [
        library[DefaultInfo],
        library[CcInfo],
    ]

_cc_17_library = rule(
    implementation = _cc_17_library_impl,
    attrs = {
        "library": attr.label(
            cfg = _add_cxxopt_std_17,
            mandatory = True,
            providers = [CcInfo],
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
    provides = [CcInfo],
)

# A cc_library that is built with -std=c++17, including all its transitive
# dependencies. This is redundant while developing Jazzer itself as the .bazelrc
# sets this flag for all build commands, but is needed when Jazzer is included
# as an external workspace.
def cc_17_library(name, visibility = None, **kwargs):
    library_name = name + "_original_"
    native.cc_library(
        name = library_name,
        visibility = ["//visibility:private"],
        **kwargs
    )

    _cc_17_library(
        name = name,
        library = library_name,
        visibility = visibility,
    )
