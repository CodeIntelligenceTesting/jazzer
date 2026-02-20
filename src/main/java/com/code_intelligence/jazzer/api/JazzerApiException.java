/*
 * Copyright 2026 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.api;

/**
 * Signals error from the Jazzer API (e.g. invalid arguments to {@link Jazzer#maximize}).
 *
 * <p>This exception is treated as a fatal error by the fuzzing engine rather than as a finding in
 * the code under test. When thrown during fuzzing, it stops the current fuzz test with an error
 * instead of reporting a bug in the fuzz target.
 */
public final class JazzerApiException extends RuntimeException {
  public JazzerApiException(String message) {
    super(message);
  }

  public JazzerApiException(String message, Throwable cause) {
    super(message, cause);
  }

  public JazzerApiException(Throwable cause) {
    super(cause);
  }
}
