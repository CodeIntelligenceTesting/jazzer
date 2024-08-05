// Copyright 2024 Code Intelligence GmbH
//
// By downloading, you agree to the Code Intelligence Jazzer Terms and
// Conditions.
//
// The Code Intelligence Jazzer Terms and Conditions are provided in
// LICENSE-JAZZER.txt located in the root directory of the project.

#include <rules_jni.h>

#include "gtest/gtest.h"

int main(int argc, char **argv) {
  rules_jni_init(argv[0]);
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
