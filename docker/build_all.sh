#
# Copyright 2024 Code Intelligence GmbH
#
# By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
#
# The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
# located in the root directory of the project.
#

set -e

this_dir=$(dirname "$(realpath "$0")")
docker build --pull -t cifuzz/jazzer "$@" "$this_dir"/jazzer
docker build -t cifuzz/jazzer-autofuzz "$@" "$this_dir"/jazzer-autofuzz
