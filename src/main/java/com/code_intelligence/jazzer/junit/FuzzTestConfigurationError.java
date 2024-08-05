/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.junit;

/**
 * An {@link Error} thrown when a {@link FuzzTest} is not configured correctly, for example due to
 * unsupported parameters or invalid settings.
 */
class FuzzTestConfigurationError extends Error {
  public FuzzTestConfigurationError(String message) {
    super(message);
  }

  public FuzzTestConfigurationError(String message, Throwable cause) {
    super(message, cause);
  }
}
