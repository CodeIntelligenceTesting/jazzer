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

def jazzer_repo_name():
    # Skip over the '@'.
    repo_name = native.repository_name()[1:]
    if repo_name:
        return repo_name
    else:
        # repository_name returns "@" for the main repo. In this case, we know that the name of the
        # repository is also the name of the workspace or module we define, which is always just
        # "jazzer".
        return "jazzer"

def jazzer_repo_name_define_value():
    # One level of quoting for Starlark, one for the shell.
    return "\\\"%s\\\"" % jazzer_repo_name()

SKIP_ON_MACOS = select({
    "@platforms//os:macos": ["@platforms//:incompatible"],
    "//conditions:default": [],
})

SKIP_ON_WINDOWS = select({
    "@platforms//os:windows": ["@platforms//:incompatible"],
    "//conditions:default": [],
})
