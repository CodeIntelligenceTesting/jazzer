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

load("@rules_kotlin//kotlin:lint.bzl", "ktlint_fix", "ktlint_test")
load("@rules_kotlin//kotlin:jvm.bzl", "kt_jvm_test")
load("//bazel:compat.bzl", "SKIP_ON_WINDOWS")

# A kt_jvm_test wrapped in a java_test for Windows compatibility.
# Workaround for https://github.com/bazelbuild/rules_kotlin/issues/599: rules_kotlin can only create
# a shell wrapper script for Java targets, no native executable as is required on Windows.
def wrapped_kt_jvm_test(
        name,
        test_class,
        size = None,
        tags = None,
        timeout = None,
        visibility = None,
        **kt_jvm_test_args):
    kt_jvm_test_name = name + "_kt_"

    # Modify a copy of the tags.
    kt_jvm_test_tags = list(tags) if tags != None else []
    kt_jvm_test_tags.append("manual")
    kt_jvm_test(
        name = kt_jvm_test_name,
        test_class = test_class,
        visibility = ["//visibility:private"],
        tags = kt_jvm_test_tags,
        **kt_jvm_test_args
    )

    native.java_test(
        name = name,
        size = size,
        tags = tags,
        test_class = test_class,
        timeout = timeout,
        visibility = visibility,
        runtime_deps = [
            ":" + kt_jvm_test_name,
        ],
    )

def ktlint(name = "ktlint"):
    ktlint_test(
        name = name + "_test",
        srcs = native.glob(["**/*.kt"]),
        config = Label("//bazel/toolchains:ktlint_config"),
        target_compatible_with = SKIP_ON_WINDOWS,
    )

    ktlint_fix(
        name = name + "_fix",
        srcs = native.glob(["**/*.kt"]),
        config = Label("//bazel/toolchains:ktlint_config"),
        target_compatible_with = SKIP_ON_WINDOWS,
    )
