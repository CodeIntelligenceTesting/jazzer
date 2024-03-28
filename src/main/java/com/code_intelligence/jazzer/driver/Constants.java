/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.driver;

public final class Constants {

  // Default value of the libFuzzer -error_exitcode flag.
  public static final int JAZZER_FINDING_EXIT_CODE = 77;

  // Success exit code if no finding/error was detected.
  public static final int JAZZER_SUCCESS_EXIT_CODE = 0;

  // Error exit code if the fuzz test could not be executed or
  // other configuration errors occurred.
  public static final int JAZZER_ERROR_EXIT_CODE = 1;

  private Constants() {}
}
