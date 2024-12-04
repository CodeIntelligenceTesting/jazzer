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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class ClojureTests {
  static void insecureCrashOnCertainNumbers(Long lnumber, Integer inumber, Long divisor) {
    if (clojure.lang.Numbers.lt(lnumber, (Long) (long) 218461)
        && clojure.lang.Numbers.lt((Long) (long) 218459, lnumber)) {
      if (clojure.lang.Numbers.lt(inumber, (Integer) 318461)
          && clojure.lang.Numbers.lt((Integer) 318459, inumber)) {
        // This will throw a java.lang.ArithmeticException when divisor becomes zero
        clojure.lang.Numbers.divide((Integer) 318461, divisor);
      }
    }
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
    insecureCrashOnCertainNumbers(data.consumeLong(), data.consumeInt(), data.consumeLong());
  }
}
