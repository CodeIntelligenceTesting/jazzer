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

package com.example;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import java.util.ArrayList;

/**
 * Regression test for https://github.com/CodeIntelligence/jazzer/issues/878.
 *
 * <p>When generating a coverage report at shutdown, any use of hooked method would trigger custom
 * hook dispatch. If the hook class is no longer loadable at that point, the JVM throws
 * NoClassDefFoundError.
 *
 * <p>This test verifies that hooks are disabled during coverage report generation by checking
 * whether the hook's system property marker was set after the last fuzzer iteration. The shutdown
 * sequence calls coverage report generation BEFORE fuzzerTearDown, so if hooks fire during report
 * generation, the property will be set when fuzzerTearDown runs.
 */
public class CoverageWithHooksFuzzer {
  public static void fuzzerTestOneInput(byte[] data) {
    // Use ArrayList so the hook fires during fuzzing.
    ArrayList<Byte> list = new ArrayList<>();
    for (byte b : data) {
      list.add(b);
    }
    // Verify the hook actually fired during this iteration.
    if (!"true".equals(System.getProperty("jazzer.test.hook.called"))) {
      throw new IllegalStateException("Hook did not fire during fuzzing");
    }
    // Clear the property after all ArrayList usage in this iteration.
    // If hooks fire during coverage report generation (after the last iteration),
    // the property will be set again.
    System.clearProperty("jazzer.test.hook.called");
    if (list.size() > 3) {
      throw new FuzzerSecurityIssueLow("found enough bytes");
    }
  }

  public static void fuzzerTearDown() {
    // fuzzerTearDown is called AFTER coverage report generation in the shutdown sequence.
    // If hooks were active during coverage report generation, use of hooked classes
    // would have triggered our hook, setting the property.
    if ("true".equals(System.getProperty("jazzer.test.hook.called"))) {
      throw new IllegalStateException("Hook was called during coverage report generation");
    }
  }
}
