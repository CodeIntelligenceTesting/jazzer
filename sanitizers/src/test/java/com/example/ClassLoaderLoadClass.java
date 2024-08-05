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

public class ClassLoaderLoadClass {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws InterruptedException {
    String input = data.consumeRemainingAsAsciiString();
    try {
      // create an instance to trigger class initialization
      ClassLoaderLoadClass.class.getClassLoader().loadClass(input).newInstance();
      // TODO(khaled): this fails to reproduce the finding. It seems that this is related to not
      // throwing a hard-to-catch error when not running in the fuzzing mode.
      // ClassLoaderLoadClass.class.getClassLoader().loadClass(input).getConstructor().newInstance();
    } catch (ClassNotFoundException | InstantiationException | IllegalAccessException ignored) {
    }
  }
}
