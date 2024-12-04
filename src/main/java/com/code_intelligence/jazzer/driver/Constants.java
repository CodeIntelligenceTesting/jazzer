/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
