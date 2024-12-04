#!/usr/bin/env sh
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


# Use just like `bazel test` to generate and open an HTML coverage report.
# Requires a local installation of Perl.

RUNFILES_ROOT=$PWD
cd "$BUILD_WORKSPACE_DIRECTORY" || exit 1
if ! bazel coverage "${@:-//...}";
then
  exit $?
fi
"$RUNFILES_ROOT"/../genhtml/file/genhtml -o coverage \
  --prefix "$PWD" \
  --title "bazel coverage ${*:-//...}" \
  bazel-out/_coverage/_coverage_report.dat
xdg-open coverage/index.html > /dev/null 2>&1
