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

load("@bazel_skylib//rules:write_file.bzl", "write_file")

def _add_cxxopt_std_17_impl(settings, attr):
    STD_CXX_17_CXXOPTS = ["/std:c++17" if attr.is_windows else "-std=c++17"]
    return {
        "//command_line_option:cxxopt": settings["//command_line_option:cxxopt"] + STD_CXX_17_CXXOPTS,
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
        # Workaround for https://github.com/bazelbuild/bazel/issues/9442.
        DefaultInfo(
            data_runfiles = library[DefaultInfo].data_runfiles,
            default_runfiles = library[DefaultInfo].default_runfiles,
            files = library[DefaultInfo].files,
        ),
        library[CcInfo],
        coverage_common.instrumented_files_info(
            ctx,
            dependency_attributes = ["library"],
        ),
    ]

_cc_17_library = rule(
    implementation = _cc_17_library_impl,
    attrs = {
        "is_windows": attr.bool(),
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
    library_name = name + "_original_do_not_use_"
    kwargs.setdefault("tags", []).append("manual")
    native.cc_library(
        name = library_name,
        visibility = ["//visibility:private"],
        **kwargs
    )

    _cc_17_library(
        name = name,
        is_windows = select({
            "@platforms//os:windows": True,
            "//conditions:default": False,
        }),
        library = library_name,
        visibility = visibility,
    )

# A drop-in replacement for cc_binary that behaves identically on non-Windows platforms.
# On Windows, the resulting executable will dynamically export the symbols specified in win_exports.
# Furthermore, the following additional targets will be available:
#
# * <name>.if:  An interface library that dynamic libraries can be link against if they depend on
#               symbols from the executable.
# * <name>.def: The .def file generated for this executable. Specify this as the win_def_file of
#               another cc_binary to export the same symbols.
#
# Based on an idea brought up in
#   https://github.com/bazelbuild/bazel/issues/15107#issuecomment-1077414779.
def cc_interface_binary(
        name,
        win_exports,
        data = None,
        tags = None,
        visibility = None,
        **kwargs):
    dll_name = "_%s_dll" % name
    win_def_name = "%s_def" % name
    win_def_file_name = "%s.def" % name
    interface_filegroup_name = "_%s.if" % name
    interface_import_name = "%s.if" % name

    def_library_name = name + ".exe"
    write_file(
        name = win_def_name,
        out = win_def_file_name,
        content = [
            "LIBRARY   " + def_library_name,
            "EXPORTS",
        ] + [
            "   {symbol}   @{id}".format(
                id = id,
                symbol = symbol,
            )
            for id, symbol in enumerate(win_exports, 1)
        ],
        tags = ["manual"],
        visibility = visibility,
    )

    native.cc_binary(
        name = name,
        data = data,
        tags = tags,
        visibility = visibility,
        win_def_file = ":" + win_def_name,
        **kwargs
    )

    # Intentionally omits data so that the main binary target can data-depend on
    # a shared library dynamically linked against it without creating a cyclic
    # dependency.
    native.cc_binary(
        name = dll_name,
        linkshared = True,
        tags = ["manual"],
        visibility = ["//visibility:private"],
        win_def_file = ":" + win_def_name,
        **kwargs
    )

    native.filegroup(
        name = interface_filegroup_name,
        srcs = [":" + dll_name],
        output_group = "interface_library",
        tags = ["manual"],
        visibility = ["//visibility:private"],
    )

    native.cc_import(
        name = interface_import_name,
        interface_library = ":" + interface_filegroup_name,
        system_provided = True,
        tags = ["manual"],
        visibility = visibility,
    )
