/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

public class AutofuzzAssertionErrorTarget {
  public static void autofuzz(byte[] b) {
    assert b == null || b.length <= 5 || b[3] != 7;
  }
}
