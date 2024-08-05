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
"$this_dir"/build_all.sh --no-cache

docker push cifuzz/jazzer
docker push cifuzz/jazzer-autofuzz
