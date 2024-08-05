#
# Copyright 2024 Code Intelligence GmbH
#
# By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
#
# The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
# located in the root directory of the project.
#

JMH_TEST_ARGS = [
    # Fail fast on any exceptions produced by benchmarks.
    "-foe true",
    "-wf 0",
    "-f 1",
    "-wi 0",
    "-i 1",
    "-r 1s",
    "-w 1s",
]
