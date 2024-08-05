/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

public class AutofuzzIgnoreTarget {
  @SuppressWarnings("unused")
  public void doStuff(String data) {
    if (data.isEmpty()) {
      throw new NullPointerException();
    }
    if (data.length() < 10) {
      throw new IllegalArgumentException();
    }
    throw new RuntimeException();
  }
}
