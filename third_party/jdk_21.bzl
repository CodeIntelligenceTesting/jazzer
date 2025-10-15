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

load("@rules_java//toolchains:remote_java_repository.bzl", "remote_java_repository")

def _remote_jdk21_repos(_):
    remote_java_repository(
        name = "remote_jdk21_linux",
        target_compatible_with = [
            "@platforms//os:linux",
            "@platforms//cpu:x86_64",
        ],
        sha256 = "63f56bbb46958cf57352fba08f2755e0953799195e5545acc0c8a92920beff1e",
        strip_prefix = "zulu21.44.17-ca-jdk21.0.8-linux_x64",
        urls = [
            "https://cdn.azul.com/zulu/bin/zulu21.44.17-ca-jdk21.0.8-linux_x64.tar.gz",
        ],
        version = "21",
    )
    remote_java_repository(
        name = "remote_jdk21_linux_aarch64",
        target_compatible_with = [
            "@platforms//os:linux",
            "@platforms//cpu:aarch64",
        ],
        sha256 = "ff7f2edd1d5c153cb6cb493a3aa3523453e29a05ec513b25c24aa1477ec0c722",
        strip_prefix = "zulu21.44.17-ca-jdk21.0.8-linux_aarch64",
        urls = [
            "https://cdn.azul.com/zulu/bin/zulu21.44.17-ca-jdk21.0.8-linux_aarch64.tar.gz",
        ],
        version = "21",
    )
    remote_java_repository(
        name = "remote_jdk21_macos_aarch64",
        target_compatible_with = [
            "@platforms//os:macos",
            "@platforms//cpu:aarch64",
        ],
        sha256 = "d22ce05fea3e3f28c8c59f2c348bc78ee967bf1289a4fb28796cc0177ff6c8db",
        strip_prefix = "zulu21.44.17-ca-jdk21.0.8-macosx_aarch64",
        urls = [
            "https://cdn.azul.com/zulu/bin/zulu21.44.17-ca-jdk21.0.8-macosx_aarch64.tar.gz",
        ],
        version = "21",
    )
    remote_java_repository(
        name = "remote_jdk21_macos",
        target_compatible_with = [
            "@platforms//os:macos",
            "@platforms//cpu:x86_64",
        ],
        sha256 = "2af080500b5cc286a6353187c7c59b5aafcb3edc29c1c87d1fd71ba2d6a523f1",
        strip_prefix = "zulu21.44.17-ca-jdk21.0.8-macosx_x64",
        urls = [
            "https://cdn.azul.com/zulu/bin/zulu21.44.17-ca-jdk21.0.8-macosx_x64.tar.gz",
        ],
        version = "21",
    )
    remote_java_repository(
        name = "remote_jdk21_windows",
        target_compatible_with = [
            "@platforms//os:windows",
            "@platforms//cpu:x86_64",
        ],
        sha256 = "f47dbd00384cb759f86a066be7545e467e5764f4653a237c32c07da96dc1c43b",
        strip_prefix = "zulu21.44.17-ca-jdk21.0.8-win_x64",
        urls = [
            "https://cdn.azul.com/zulu/bin/zulu21.44.17-ca-jdk21.0.8-win_x64.zip",
        ],
        version = "21",
    )

remote_jdk21_repos = module_extension(_remote_jdk21_repos)
