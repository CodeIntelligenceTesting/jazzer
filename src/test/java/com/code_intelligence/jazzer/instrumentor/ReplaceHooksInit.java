/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.instrumentor;

public class ReplaceHooksInit {
  public boolean initialized;

  public ReplaceHooksInit() {}

  @SuppressWarnings("unused")
  public ReplaceHooksInit(boolean initialized, String ignored) {
    this.initialized = initialized;
  }
}
