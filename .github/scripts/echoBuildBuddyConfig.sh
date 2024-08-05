#!/usr/bin/env bash

#
# Copyright 2024 Code Intelligence GmbH
#
# By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
#
# The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
# located in the root directory of the project.
#

if [ -n "${1}" ]; then
  echo "BUILD_BUDDY_CONFIG=--config=ci --remote_header=x-buildbuddy-api-key=${1}";
else
  echo "";
fi
