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

import java.util.Random;

public class CoverageInstrumentationSpecialCasesTarget {
  public ReturnClass newAfterJump() {
    if (new Random().nextBoolean()) {
      throw new RuntimeException("");
    }
    return new ReturnClass(new Random().nextBoolean() ? "foo" : "bar");
  }

  public int newAndTryCatch() {
    new Random();
    try {
      new Random();
      return 2;
    } catch (RuntimeException e) {
      new Random();
      return 1;
    }
  }

  public static class ReturnClass {
    public ReturnClass(String content) {}
  }
}
