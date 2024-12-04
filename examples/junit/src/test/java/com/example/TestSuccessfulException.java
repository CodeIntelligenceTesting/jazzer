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

package com.example;

/**
 * An exception thrown by a java_fuzz_target_test if the test run is considered successful.
 *
 * <p>Use this instead of a generic exception to ensure that tests do not pass if such a generic
 * exception is thrown unexpectedly.
 *
 * <p>Use this instead of {@link com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow} and other
 * Jazzer-specific exceptions as using them in tests leads to classloader issues: The exception
 * classes may be loaded both in the bootstrap and the system classloader depending on when exactly
 * the agent (and with it the bootstrap jar) is installed, which can cause in `instanceof` checks
 * failing unexpectedly.
 */
public class TestSuccessfulException extends Exception {
  public TestSuccessfulException(String message) {
    super(message);
  }
}
