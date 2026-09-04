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
package com.code_intelligence.jazzer.sanitizers;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Regression tests for the {@code clojure.lang.Var#getRawRoot} AFTER hook. A non-dynamic Clojure
 * var can have a {@code null} root, e.g. {@code (def ^:private bb? (System/getProperty ...))} in
 * riddley 0.2.2 on the JVM, which previously caused a NullPointerException in the hook.
 */
public class ClojureLangHooksTest {
  @Test
  void clojureMarkContainsDoesNotThrowOnNullResult() {
    assertDoesNotThrow(() -> ClojureLangHooks.clojureMarkContains(null, null, null, 0, null));
  }

  @Test
  void clojureMarkContainsIgnoresNonStringContainsFunctions() {
    Object func = new Object();
    ClojureLangHooks.clojureMarkContains(null, null, null, 0, func);
    assertFalse(ClojureLangHooks.stringContainsFuncs.get().contains(func));
  }

  @Test
  void clojureMarkContainsTracksStringContainsFunctions() throws Exception {
    Object func =
        Class.forName("clojure.string$includes_QMARK_").getDeclaredConstructor().newInstance();
    ClojureLangHooks.clojureMarkContains(null, null, null, 0, func);
    assertTrue(ClojureLangHooks.stringContainsFuncs.get().contains(func));
  }
}
