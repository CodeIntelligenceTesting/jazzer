/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;

@SuppressWarnings("unused")
public class AutofuzzInnerClassTarget {
  public static class Middle {
    public static class Inner {
      public void test(int a, int b) {
        if (a == b) {
          throw new FuzzerSecurityIssueLow("Finished Autofuzz Target");
        }
      }
    }
  }
}
