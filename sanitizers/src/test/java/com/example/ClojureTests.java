/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
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
