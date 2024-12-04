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

def _remote_jdk8_repos(_):
    remote_java_repository(
        name = "remote_jdk8_linux",
        target_compatible_with = [
            "@platforms//os:linux",
            "@platforms//cpu:x86_64",
        ],
        sha256 = "39dc809ef8e88eff49d2eaeb48580729888486d56d846559b719da9c545e2884",
        strip_prefix = "zulu8.74.0.17-ca-jdk8.0.392-linux_x64",
        urls = [
            "https://cdn.azul.com/zulu/bin/zulu8.74.0.17-ca-jdk8.0.392-linux_x64.tar.gz",
        ],
        version = "8",
    )
    remote_java_repository(
        name = "remote_jdk8_macos_aarch64",
        target_compatible_with = [
            "@platforms//os:macos",
            "@platforms//cpu:aarch64",
        ],
        sha256 = "51b5187e3d50fd469a67c4a9e2e816cb14e6247a51a24d8a96b88d2bdc512714",
        strip_prefix = "zulu8.74.0.17-ca-jdk8.0.392-macosx_aarch64",
        urls = [
            "https://cdn.azul.com/zulu/bin/zulu8.74.0.17-ca-jdk8.0.392-macosx_aarch64.tar.gz",
        ],
        version = "8",
    )
    remote_java_repository(
        name = "remote_jdk8_macos",
        target_compatible_with = [
            "@platforms//os:macos",
            "@platforms//cpu:x86_64",
        ],
        sha256 = "ab29ecd51033c8804cd0711c225266c3b757518c90040cb279e329bf1eb9b387",
        strip_prefix = "zulu8.74.0.17-ca-jdk8.0.392-macosx_x64",
        urls = [
            "https://cdn.azul.com/zulu/bin/zulu8.74.0.17-ca-jdk8.0.392-macosx_x64.tar.gz",
        ],
        version = "8",
    )
    remote_java_repository(
        name = "remote_jdk8_windows",
        target_compatible_with = [
            "@platforms//os:windows",
            "@platforms//cpu:x86_64",
        ],
        sha256 = "3ba91c758ca93c527983ed3f409ee504c6fc33e0a697672db9c959abba10e38d",
        strip_prefix = "zulu8.74.0.17-ca-jdk8.0.392-win_x64",
        urls = [
            "https://cdn.azul.com/zulu/bin/zulu8.74.0.17-ca-jdk8.0.392-win_x64.zip",
        ],
        version = "8",
    )

remote_jdk8_repos = module_extension(_remote_jdk8_repos)
