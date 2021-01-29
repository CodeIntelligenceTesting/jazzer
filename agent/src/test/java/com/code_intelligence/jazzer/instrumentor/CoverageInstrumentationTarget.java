// Copyright 2021 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.code_intelligence.jazzer.instrumentor;

import java.util.HashMap;
import java.util.Map;

public class CoverageInstrumentationTarget implements DynamicTestContract {
  // Constructor loc: constructorStart

  volatile int int1 = 3;
  volatile int int2 = 213234;

  @Override
  public Map<String, Boolean> selfCheck() {
    // loc: selfCheckStart
    Map<String, Boolean> results = new HashMap<>();

    results.put("for0", false);
    results.put("for1", false);
    results.put("for2", false);
    results.put("for3", false);
    results.put("for4", false);
    results.put("foobar", false);
    results.put("baz", true);

    if (int1 < int2) {
      // loc: ifFirstBranch
      results.put("block1", true);
    } else {
      // loc: not reached
      results.put("block2", false);
    }
    // loc: ifEnd

    for (int i = 0; /* loc: outerForCondition */ i < 2; /* loc: outerForIncrementCounter */ i++) {
      /* loc: outerForBody */
      for (int j = 0; /* loc: innerForCondition */ j < 5; /* loc: innerForIncrementCounter */ j++) {
        // loc: innerForBody
        results.put("for" + j,
            i != 0); // != 0 loc: innerForBodyIfSecondRun, == 0 loc: innerForBodyIfFirstRun
      }
    }
    // loc: outerForAfter

    foo(results);
    // baz(results);

    return results;
  }

  private void foo(Map<String, Boolean> results) {
    // loc: fooStart
    bar(results);
  }

  private void bar(Map<String, Boolean> results) {
    // loc: barStart
    results.put("foobar", true);
  }

  // Not called.
  @SuppressWarnings("unused")
  private void baz(Map<String, Boolean> results) {
    // loc: not reached
    results.put("baz", false);
  }
}
