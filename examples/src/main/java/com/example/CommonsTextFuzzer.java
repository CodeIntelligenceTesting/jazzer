/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 *
 * This file also contains code licensed under Apache2 license.
 */

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.apache.commons.text.StringSubstitutor;

public class CommonsTextFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      StringSubstitutor.createInterpolator().replace(data.consumeAsciiString(20));
    } catch (java.lang.IllegalArgumentException
        | java.lang.ArrayIndexOutOfBoundsException ignored) {
    }
  }
}
