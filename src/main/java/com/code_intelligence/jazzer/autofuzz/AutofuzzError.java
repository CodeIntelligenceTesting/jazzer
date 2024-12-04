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

package com.code_intelligence.jazzer.autofuzz;

/** An error indicating an internal error in the autofuzz functionality. */
public class AutofuzzError extends Error {
  private static final String MESSAGE_TRAILER =
      String.format(
          "%nPlease file an issue at:%n "
              + " https://github.com/CodeIntelligenceTesting/jazzer/issues/new/choose");

  public AutofuzzError(String message) {
    super(message + MESSAGE_TRAILER);
  }

  public AutofuzzError(String message, Throwable cause) {
    super(message + MESSAGE_TRAILER, cause);
  }
}
