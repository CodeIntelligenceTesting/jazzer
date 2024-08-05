#!/usr/bin/env sh
#
# Copyright 2024 Code Intelligence GmbH
#
# By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
#
# The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
# located in the root directory of the project.
#

[ -f "$1" ] || exit 1
JAR="$2/bin/jar"
[ -e "$JAR" ] || exit 1
# List all files in the jar and exclude an allowed list of files.
# Since grep fails if there is no match, ! ... | grep ... fails if there is a
# match.
! "$JAR" tf "$1" | \
  grep -v \
    -e '^com/$' \
    -e '^com/code_intelligence/$' \
    -e '^com/code_intelligence/jazzer/$' \
    -e '^com/code_intelligence/jazzer/junit/' \
    -e '^com/code_intelligence/jazzer/sanitizers/$' \
    -e '^com/code_intelligence/jazzer/sanitizers/Constants.class$' \
    -e '^META-INF/$' \
    -e '^META-INF/MANIFEST.MF$' \
    -e '^META-INF/services/$' \
    -e '^META-INF/services/org.junit.platform.engine.TestEngine$'
