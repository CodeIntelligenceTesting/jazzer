/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.instrumentor;

/**
 * Helper interface used to call methods on instances of ReplaceHooksTarget classes loaded via
 * different class loaders.
 */
public interface ReplaceHooksTargetContract extends DynamicTestContract {
  void pass(String test);
}
