/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
