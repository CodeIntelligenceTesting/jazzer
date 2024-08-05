#!/usr/bin/env sh
#
# Copyright 2024 Code Intelligence GmbH
#
# By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
#
# The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
# located in the root directory of the project.
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
