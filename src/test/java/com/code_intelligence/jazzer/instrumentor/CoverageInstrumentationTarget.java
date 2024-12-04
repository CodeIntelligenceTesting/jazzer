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

package com.code_intelligence.jazzer.instrumentor;

import java.util.HashMap;
import java.util.Map;

public class CoverageInstrumentationTarget implements DynamicTestContract {
  volatile int int1 = 3;
  volatile int int2 = 213234;

  @Override
  public Map<String, Boolean> selfCheck() {
    HashMap<String, Boolean> results = new HashMap<>();

    results.put("for0", false);
    results.put("for1", false);
    results.put("for2", false);
    results.put("for3", false);
    results.put("for4", false);
    results.put("foobar", false);
    results.put("baz", true);

    if (int1 < int2) {
      results.put("block1", true);
    } else {
      results.put("block2", false);
    }

    for (int i = 0; i < 2; i++) {
      for (int j = 0; j < 5; j++) {
        results.put("for" + j, i != 0);
      }
    }

    foo(results);

    return results;
  }

  private void foo(HashMap<String, Boolean> results) {
    bar(results);
  }

  // The use of Map instead of HashMap is deliberate here: Since Map#put can throw exceptions, the
  // invocation should be instrumented for coverage.
  private void bar(Map<String, Boolean> results) {
    results.put("foobar", true);
  }

  @SuppressWarnings("unused")
  private void baz(HashMap<String, Boolean> results) {
    results.put("baz", false);
  }
}
