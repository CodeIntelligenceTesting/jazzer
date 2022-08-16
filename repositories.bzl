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

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_jar")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def jazzer_dependencies():
    maybe(
        http_archive,
        name = "platforms",
        sha256 = "379113459b0feaf6bfbb584a91874c065078aa673222846ac765f86661c27407",
        urls = [
            "https://mirror.bazel.build/github.com/bazelbuild/platforms/releases/download/0.0.5/platforms-0.0.5.tar.gz",
            "https://github.com/bazelbuild/platforms/releases/download/0.0.5/platforms-0.0.5.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "bazel_skylib",
        sha256 = "f7be3474d42aae265405a592bb7da8e171919d74c16f082a5457840f06054728",
        urls = [
            "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.2.1/bazel-skylib-1.2.1.tar.gz",
            "https://github.com/bazelbuild/bazel-skylib/releases/download/1.2.1/bazel-skylib-1.2.1.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "io_bazel_rules_kotlin",
        sha256 = "a57591404423a52bd6b18ebba7979e8cd2243534736c5c94d35c89718ea38f94",
        url = "https://github.com/bazelbuild/rules_kotlin/releases/download/v1.6.0/rules_kotlin_release.tgz",
    )

    maybe(
        http_archive,
        name = "com_google_absl",
        sha256 = "4208129b49006089ba1d6710845a45e31c59b0ab6bff9e5788a87f55c5abd602",
        strip_prefix = "abseil-cpp-20220623.0",
        url = "https://github.com/abseil/abseil-cpp/archive/refs/tags/20220623.0.tar.gz",
    )

    maybe(
        http_archive,
        name = "com_github_johnynek_bazel_jar_jar",
        sha256 = "138a33a5c6ed9355e4411caa22f2fe45460b7e1e4468cbc29f7955367d7a001a",
        strip_prefix = "bazel_jar_jar-commit-d97cfd22d47cba9a20708fa092f20348b72fb5ed",
        url = "https://github.com/CodeIntelligenceTesting/bazel_jar_jar/archive/refs/tags/commit-d97cfd22d47cba9a20708fa092f20348b72fb5ed.tar.gz",
    )

    maybe(
        http_archive,
        name = "com_github_jhalterman_typetools",
        build_file = Label("//third_party:typetools.BUILD"),
        sha256 = "4e11a613aebb3c35deef58d5d942e44802da1a6c6ef7f127419261f00a0a082c",
        strip_prefix = "typetools-commit-887153d2a9adf032fac9f145594d0a0248618d48",
        url = "https://github.com/CodeIntelligenceTesting/typetools/archive/refs/tags/commit-887153d2a9adf032fac9f145594d0a0248618d48.tar.gz",
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
        sha256 = "47f0c566ef93fbca2fe94ae8b964d9bf2cb5b31be0efa66e9684b096e54042c1",
        strip_prefix = "rules_jni-0.5.2",
        url = "https://github.com/fmeum/rules_jni/archive/refs/tags/v0.5.2.tar.gz",
    )

    maybe(
        http_jar,
        name = "net_bytebuddy_byte_buddy_agent",
        sha256 = "25eed4301bbde3724a4bac0e7fe4a0b371c64b5fb40160b29480de3afd04efd5",
        url = "https://repo1.maven.org/maven2/net/bytebuddy/byte-buddy-agent/1.12.13/byte-buddy-agent-1.12.13.jar",
    )

    maybe(
        http_jar,
        name = "org_ow2_asm_asm",
        sha256 = "1263369b59e29c943918de11d6d6152e2ec6085ce63e5710516f8c67d368e4bc",
        url = "https://repo1.maven.org/maven2/org/ow2/asm/asm/9.3/asm-9.3.jar",
    )

    maybe(
        http_jar,
        name = "org_ow2_asm_asm_commons",
        sha256 = "a347c24732db2aead106b6e5996a015b06a3ef86e790a4f75b61761f0d2f7f39",
        url = "https://repo1.maven.org/maven2/org/ow2/asm/asm-commons/9.3/asm-commons-9.3.jar",
    )

    maybe(
        http_jar,
        name = "org_ow2_asm_asm_tree",
        sha256 = "ae629c2609f39681ef8d140a42a23800464a94f2d23e36d8f25cd10d5e4caff4",
        url = "https://repo1.maven.org/maven2/org/ow2/asm/asm-tree/9.3/asm-tree-9.3.jar",
    )

    maybe(
        http_archive,
        name = "jazzer_com_github_gflags_gflags",
        patches = [
            Label("//third_party:gflags-use-double-dash-args.patch"),
        ],
        sha256 = "34af2f15cf7367513b352bdcd2493ab14ce43692d2dcd9dfc499492966c64dcf",
        strip_prefix = "gflags-2.2.2",
        url = "https://github.com/gflags/gflags/archive/refs/tags/v2.2.2.tar.gz",
    )

    maybe(
        http_archive,
        name = "jazzer_jacoco",
        build_file = Label("//third_party:jacoco_internal.BUILD"),
        patches = [
            Label("//third_party:jacoco-make-probe-adapter-subclassable.patch"),
            Label("//third_party:jacoco-make-probe-inserter-subclassable.patch"),
        ],
        sha256 = "c603cfcc5f3d95ecda46fb369dc54c82a453bb6b640a605c3970607d10896725",
        strip_prefix = "jacoco-0.8.8",
        url = "https://github.com/jacoco/jacoco/archive/refs/tags/v0.8.8.tar.gz",
    )

    maybe(
        http_archive,
        name = "jazzer_libfuzzer",
        build_file = Label("//third_party:libFuzzer.BUILD"),
        sha256 = "3732ff706e5d049dbc76c2078d9e3ad265c6ccbe1b9ed749ae199df0f3118aac",
        strip_prefix = "llvm-project-jazzer-2022-08-12/compiler-rt/lib/fuzzer",
        url = "https://github.com/CodeIntelligenceTesting/llvm-project-jazzer/archive/refs/tags/2022-08-12.tar.gz",
    )
