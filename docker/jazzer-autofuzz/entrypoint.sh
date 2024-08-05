#!/usr/bin/env bash
#
# Copyright 2024 Code Intelligence GmbH
#
# By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
#
# The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
# located in the root directory of the project.
#

set -e

CP="$(/app/coursier.jar fetch --classpath "$1")"
/app/jazzer \
  --cp="$CP" \
  --autofuzz="$2" \
  "${@:3}"
