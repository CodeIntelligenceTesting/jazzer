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

"""Contains the external dependencies required to build Jazzer (but not the examples)."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def jazzer_dependencies():
    maybe(
        http_archive,
        name = "platforms",
        sha256 = "079945598e4b6cc075846f7fd6a9d0857c33a7afc0de868c2ccb96405225135d",
        urls = [
            "https://mirror.bazel.build/github.com/bazelbuild/platforms/releases/download/0.0.4/platforms-0.0.4.tar.gz",
            "https://github.com/bazelbuild/platforms/releases/download/0.0.4/platforms-0.0.4.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "bazel_skylib",
        sha256 = "c6966ec828da198c5d9adbaa94c05e3a1c7f21bd012a0b29ba8ddbccb2c93b0d",
        urls = [
            "https://github.com/bazelbuild/bazel-skylib/releases/download/1.1.1/bazel-skylib-1.1.1.tar.gz",
            "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.1.1/bazel-skylib-1.1.1.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "io_bazel_rules_kotlin",
        sha256 = "6cbd4e5768bdfae1598662e40272729ec9ece8b7bded8f0d2c81c8ff96dc139d",
        url = "https://github.com/bazelbuild/rules_kotlin/releases/download/v1.5.0-beta-4/rules_kotlin_release.tgz",
    )

    maybe(
        http_archive,
        name = "com_google_glog",
        repo_mapping = {"@com_github_gflags_gflags": "@jazzer_com_github_gflags_gflags"},
        sha256 = "5a39d51a6058348e6b683f5343a24d94e01c518c7a045101045e301a27efab13",
        strip_prefix = "glog-a4a725d547a6c1329607db50af044c4fa329e07a",
        url = "https://github.com/google/glog/archive/a4a725d547a6c1329607db50af044c4fa329e07a.tar.gz",
    )

    maybe(
        http_archive,
        name = "com_google_absl",
        sha256 = "5e1cbf25bf501f8e37866000a6052d02dbdd7b19a5b592251c59a4c9aa5c71ae",
        strip_prefix = "abseil-cpp-f2dbd918d8d08529800eb72f23bd2829f92104a4",
        url = "https://github.com/abseil/abseil-cpp/archive/f2dbd918d8d08529800eb72f23bd2829f92104a4.zip",
    )

    maybe(
        http_archive,
        name = "com_github_johnynek_bazel_jar_jar",
        sha256 = "97c5f862482a05f385bd8f9d28a9bbf684b0cf3fae93112ee96f3fb04d34b193",
        strip_prefix = "bazel_jar_jar-171f268569384c57c19474b04aebe574d85fde0d",
        url = "https://github.com/johnynek/bazel_jar_jar/archive/171f268569384c57c19474b04aebe574d85fde0d.tar.gz",
    )

    maybe(
        http_archive,
        name = "com_github_jhalterman_typetools",
        build_file = Label("//third_party:typetools.BUILD"),
        sha256 = "754f46de7d4c278cee2d4dba3c09ebe08fde03d0e67fc85d700611d9cdfb7868",
        strip_prefix = "typetools-887153d2a9adf032fac9f145594d0a0248618d48",
        url = "https://github.com/jhalterman/typetools/archive/887153d2a9adf032fac9f145594d0a0248618d48.tar.gz",
    )

    maybe(
        http_archive,
        build_file = Label("//third_party:classgraph.BUILD"),
        name = "com_github_classgraph_classgraph",
        sha256 = "535159d80c163d5b4d025c402b4562c92ed2d6d963db8c6c5255c0eb2c4e9f39",
        strip_prefix = "classgraph-classgraph-4.8.128",
        url = "https://github.com/classgraph/classgraph/archive/refs/tags/classgraph-4.8.128.tar.gz",
    )

    maybe(
        http_archive,
        name = "fmeum_rules_jni",
        sha256 = "8d685e381cb625e11fac330085de2ebc13ad497d30c4e9b09beb212f7c27e8e7",
        url = "https://github.com/fmeum/rules_jni/releases/download/v0.3.0/rules_jni-v0.3.0.tar.gz",
    )

    maybe(
        http_archive,
        build_file = Label("//third_party:asm.BUILD"),
        name = "jazzer_ow2_asm",
        sha256 = "7b596cc584b241619911e99c5c96366fccd533b1a50b8720c151c2f74b5915e3",
        strip_prefix = "asm-ASM_9_2",
        url = "https://gitlab.ow2.org/asm/asm/-/archive/ASM_9_2/asm-ASM_9_2.tar.gz",
    )

    maybe(
        http_archive,
        name = "jazzer_com_github_gflags_gflags",
        patches = [
            Label("//third_party:gflags-use-double-dash-args.patch"),
        ],
        sha256 = "ce2931dd537eaab7dab78b25bec6136a0756ca0b2acbdab9aec0266998c0d9a7",
        strip_prefix = "gflags-827c769e5fc98e0f2a34c47cef953cc6328abced",
        url = "https://github.com/gflags/gflags/archive/827c769e5fc98e0f2a34c47cef953cc6328abced.tar.gz",
    )

    maybe(
        http_archive,
        name = "jazzer_jacoco",
        build_file = Label("//third_party:jacoco_internal.BUILD"),
        patches = [
            Label("//third_party:jacoco-make-probe-adapter-subclassable.patch"),
            Label("//third_party:jacoco-make-probe-inserter-subclassable.patch"),
        ],
        sha256 = "4a3c65b8a8ca58ffcec77288820f557ed93125e8a0b43dd7460b776c58bb8ed9",
        strip_prefix = "jacoco-0.8.7-jazzer",
        url = "https://github.com/CodeIntelligenceTesting/jacoco/archive/v0.8.7-jazzer.tar.gz",
    )

    maybe(
        http_archive,
        name = "jazzer_libfuzzer",
        build_file = Label("//third_party:libFuzzer.BUILD"),
        sha256 = "efde37ab5a9e4fff67f8cd43b701be5ea5ddb74a3bc10e4d8e91a614070145c3",
        url = "https://github.com/CodeIntelligenceTesting/llvm-project-jazzer/releases/download/2021-11-30/jazzer-libfuzzer-2021-11-30.tar.gz",
    )
