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
        sha256 = "5308fc1d8865406a49427ba24a9ab53087f17f5266a7aabbfc28823f3916e1ca",
        urls = [
            "https://mirror.bazel.build/github.com/bazelbuild/platforms/releases/download/0.0.6/platforms-0.0.6.tar.gz",
            "https://github.com/bazelbuild/platforms/releases/download/0.0.6/platforms-0.0.6.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "bazel_skylib",
        sha256 = "74d544d96f4a5bb630d465ca8bbcfe231e3594e5aae57e1edbf17a6eb3ca2506",
        urls = [
            "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.3.0/bazel-skylib-1.3.0.tar.gz",
            "https://github.com/bazelbuild/bazel-skylib/releases/download/1.3.0/bazel-skylib-1.3.0.tar.gz",
        ],
    )

    maybe(
        http_archive,
        name = "io_bazel_rules_kotlin",
        sha256 = "fd92a98bd8a8f0e1cdcb490b93f5acef1f1727ed992571232d33de42395ca9b3",
        url = "https://github.com/bazelbuild/rules_kotlin/releases/download/v1.7.1/rules_kotlin_release.tgz",
    )

    maybe(
        http_archive,
        name = "rules_jvm_external",
        sha256 = "6ebe13d95fc5549cc32b27d41c907426b16464c5aae893a163c7fe0c9051ec1d",
        # TODO: Return to the next release.
        strip_prefix = "rules_jvm_external-90280783fa4e74439b88191acafd99232ada61aa",
        url = "https://github.com/bazelbuild/rules_jvm_external/archive/90280783fa4e74439b88191acafd99232ada61aa.tar.gz",
    )

    maybe(
        http_archive,
        name = "build_bazel_apple_support",
        sha256 = "2e3dc4d0000e8c2f5782ea7bb53162f37c485b5d8dc62bb3d7d7fc7c276f0d00",
        url = "https://github.com/bazelbuild/apple_support/releases/download/1.3.2/apple_support.1.3.2.tar.gz",
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
        sha256 = "c6410314975a86b454a822f9b2647879bf521483e5f2f0d480eb165f70844a39",
        strip_prefix = "bazel_jar_jar-commit-55e3d3bf454641c496e592d77537cf8e65b241c0",
        url = "https://github.com/CodeIntelligenceTesting/bazel_jar_jar/archive/refs/tags/commit-55e3d3bf454641c496e592d77537cf8e65b241c0.tar.gz",
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
        sha256 = "600f0f8f321dd0a3b55a51409c9e96f4274a92a2660f8a8abdb3da6ed83147f4",
        strip_prefix = "classgraph-classgraph-4.8.149",
        url = "https://github.com/classgraph/classgraph/archive/refs/tags/classgraph-4.8.149.tar.gz",
    )

    maybe(
        http_archive,
        name = "fmeum_rules_jni",
        sha256 = "530a02c4d86f7bcfabd61e7de830f8c78fcb2ea70943eab8f2bfdad96620f1f5",
        strip_prefix = "rules_jni-0.7.0",
        url = "https://github.com/fmeum/rules_jni/archive/refs/tags/v0.7.0.tar.gz",
    )

    maybe(
        http_jar,
        name = "net_bytebuddy_byte_buddy_agent",
        sha256 = "1bd4b7bc71001c3a4e1d6160e2f87784fba4f8c265e30b48a6beaeea1a2e29e1",
        url = "https://repo1.maven.org/maven2/net/bytebuddy/byte-buddy-agent/1.12.17/byte-buddy-agent-1.12.17.jar",
    )

    maybe(
        http_jar,
        name = "org_ow2_asm_asm",
        sha256 = "39d0e2b3dc45af65a09b097945750a94a126e052e124f93468443a1d0e15f381",
        url = "https://repo1.maven.org/maven2/org/ow2/asm/asm/9.4/asm-9.4.jar",
    )

    maybe(
        http_jar,
        name = "org_ow2_asm_asm_commons",
        sha256 = "0c128a9ec3f33c98959272f6d16cf14247b508f58951574bcdbd2b56d6326364",
        url = "https://repo1.maven.org/maven2/org/ow2/asm/asm-commons/9.4/asm-commons-9.4.jar",
    )

    maybe(
        http_jar,
        name = "org_ow2_asm_asm_tree",
        sha256 = "c42d479cf24566a21eb20af7eeaeef4e86bdb4a886306cf72f483b65e75b2acf",
        url = "https://repo1.maven.org/maven2/org/ow2/asm/asm-tree/9.4/asm-tree-9.4.jar",
    )

    maybe(
        http_jar,
        name = "com_github_jsqlparser_jsqlparser",
        sha256 = "aed9ce32d0b35ea2a61c0fc418ba472a8e7d9789f026782310c9788a061fa9dc",
        url = "https://repo1.maven.org/maven2/com/github/jsqlparser/jsqlparser/4.5/jsqlparser-4.5.jar",
    )

    maybe(
        http_jar,
        name = "com_google_errorprone_error_prone_annotations",
        sha256 = "9e6814cb71816988a4fd1b07a993a8f21bb7058d522c162b1de849e19bea54ae",
        url = "https://repo1.maven.org/maven2/com/google/errorprone/error_prone_annotations/2.18.0/error_prone_annotations-2.18.0.jar",
    )

    maybe(
        http_jar,
        name = "com_google_errorprone_error_prone_type_annotations",
        sha256 = "d2ab73bc6807277f7463391504313e47bc3465ab1916339c8e82be633a9ab375",
        url = "https://repo1.maven.org/maven2/com/google/errorprone/error_prone_type_annotations/2.18.0/error_prone_type_annotations-2.18.0.jar",
    )

    maybe(
        http_jar,
        name = "com_google_protobuf_protobuf_java",
        sha256 = "3f3edbda9286246080f3eaf561dd6b0d5a2b1f1008f6909115c8609ceae9df87",
        # Keep in sync with com_google_protobuf in WORKSPACE.
        url = "https://repo1.maven.org/maven2/com/google/protobuf/protobuf-java/3.21.12/protobuf-java-3.21.12.jar",
    )

    maybe(
        http_archive,
        name = "jazzer_jacoco",
        build_file = Label("//third_party:jacoco_internal.BUILD"),
        patches = [
            Label("//third_party:jacoco-make-probe-adapter-subclassable.patch"),
            Label("//third_party:jacoco-make-probe-inserter-subclassable.patch"),
            Label("//third_party:jacoco-ignore-offline-instrumentation.patch"),
        ],
        sha256 = "c603cfcc5f3d95ecda46fb369dc54c82a453bb6b640a605c3970607d10896725",
        strip_prefix = "jacoco-0.8.8",
        url = "https://github.com/jacoco/jacoco/archive/refs/tags/v0.8.8.tar.gz",
    )

    maybe(
        http_archive,
        name = "jazzer_libfuzzer",
        build_file = Label("//third_party:libFuzzer.BUILD"),
        sha256 = "cfb91ee60ff03cec204e387f4af4fd4f031eb1257fd6481aa69ac748deecd1d1",
        strip_prefix = "llvm-project-jazzer-2022-12-07/compiler-rt/lib/fuzzer",
        url = "https://github.com/CodeIntelligenceTesting/llvm-project-jazzer/archive/refs/tags/2022-12-07.tar.gz",
    )
