/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.instrumentor;

import java.util.HashMap;
import java.util.Map;

// selfCheck() only passes with the hooks in AfterHooks.java applied.
public class AfterHooksTarget implements AfterHooksTargetContract {
  static Map<String, Boolean> results = new HashMap<>();
  static int timesCalled = 0;
  Boolean func1Called = false;

  public static void registerTimesCalled() {
    timesCalled++;
    results.put("hasBeenCalledTwice", timesCalled == 2);
  }

  public Map<String, Boolean> selfCheck() {
    results = new HashMap<>();

    if (results.isEmpty()) {
      registerHasFunc1BeenCalled();
      func1();
    }

    timesCalled = 0;
    registerTimesCalled();

    verifyFirstSecret("not_secret");
    getFirstSecret();

    verifySecondSecret("not_secret_at_all");
    getSecondSecret();

    verifyThirdSecret("not_the_secret");
    new StringBuilder("not_hunter3");

    return results;
  }

  public void func1() {
    func1Called = true;
  }

  public void registerHasFunc1BeenCalled() {
    results.put("hasFunc1BeenCalled", func1Called);
  }

  @SuppressWarnings("UnusedReturnValue")
  String getFirstSecret() {
    return "hunter2";
  }

  @SuppressWarnings("SameParameterValue")
  public void verifyFirstSecret(String secret) {
    results.put("verifyFirstSecret", secret.equals("hunter2"));
  }

  @SuppressWarnings("UnusedReturnValue")
  String getSecondSecret() {
    return "hunter2!";
  }

  @SuppressWarnings("SameParameterValue")
  public void verifySecondSecret(String secret) {
    results.put("verifySecondSecret", secret.equals("hunter2!"));
  }

  public void verifyThirdSecret(String secret) {
    results.put("verifyThirdSecret", secret.equals("hunter3"));
  }
}
