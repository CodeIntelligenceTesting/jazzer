/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import static org.junit.jupiter.api.Assertions.fail;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.io.IOException;
import java.util.regex.Pattern;

@SuppressWarnings("InvalidPatternSyntax")
class ValidFuzzTests {
  @FuzzTest
  void dataFuzz(FuzzedDataProvider data) {
    switch (data.consumeRemainingAsString()) {
      case "no_crash":
        return;
      case "assert":
        fail("JUnit assert failed");
      case "honeypot":
        try {
          Class.forName("jaz.Zer").newInstance();
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException ignored) {
          // Ignored, but the honeypot class should still throw an exception.
        }
      case "sanitizer_internal_class":
        try {
          new ProcessBuilder("jazze").start();
        } catch (IOException ignored) {
          // Ignored, but the sanitizer should still throw an exception.
        }
      case "sanitizer_user_class":
        try {
          Pattern.compile("[");
        } catch (Throwable ignored) {
          // Ignored, but the JUnit test should report an error even though all throwables are
          // caught - just like Jazzer would.
        }
      case "":
      default:
        throw new FuzzerSecurityIssueMedium();
    }
  }

  @FuzzTest
  void byteFuzz(byte[] data) {
    if (data.length < 1) {
      return;
    }
    if (data[0] % 2 == 0) {
      fail();
    }
  }

  @FuzzTest(maxDuration = "10s")
  void noCrashFuzz(byte[] data) {
    if (data.length < 10) {
      return;
    }
    Parser.parse(data);
  }
}
