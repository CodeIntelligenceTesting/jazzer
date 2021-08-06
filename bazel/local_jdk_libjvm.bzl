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

def _find_recursively_under_path(repository_ctx, path, basename):
    result = repository_ctx.execute([
        repository_ctx.which("sh"),
        "-c",
        """find -L "{path}" -name "{basename}" | head -1""".format(
            path = path,
            basename = basename,
        ),
    ])
    if result.return_code != 0:
        return None
    file_path = result.stdout.strip()
    if not file_path:
        return None
    return repository_ctx.path(file_path)

LIBJVM_NAMES = [
    "libjvm.dylib",
    "libjvm.so",
]

def _local_jdk_libjvm(repository_ctx):
    java_binary = str(repository_ctx.path(Label("@local_jdk//:bin/java")))
    java_home = str(repository_ctx.path(java_binary + "/../../"))

    libjvm_path = None
    for libjvm_name in LIBJVM_NAMES:
        libjvm_path = _find_recursively_under_path(repository_ctx, java_home, libjvm_name)
        if libjvm_path != None:
            break

    if libjvm_path != None:
        repository_ctx.symlink(libjvm_path, libjvm_path.basename)
        build_content = """
cc_import(
    name = "libjvm",
    shared_library = "{libjvm}",
    visibility = ["//visibility:public"],
)
""".format(libjvm = libjvm_path.basename)
        repository_ctx.file("BUILD.bazel", build_content, executable = False)

local_jdk_libjvm = repository_rule(
    implementation = _local_jdk_libjvm,
)
