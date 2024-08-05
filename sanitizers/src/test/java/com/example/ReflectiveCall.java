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

public class ReflectiveCall {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    String input = data.consumeRemainingAsAsciiString();
    if (input.startsWith("@")) {
      String className = input.substring(1);
      try {
        Class.forName(className).newInstance();
      } catch (ClassNotFoundException | InstantiationException | IllegalAccessException ignored) {
      }
    }
  }
}
