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

// selfCheck() only passes with the hooks in BeforeHooks.java applied.
public class BeforeHooksTarget implements BeforeHooksTargetContract {
  private static int timesCalled = 0;
  Map<String, Boolean> results = new HashMap<>();
  Boolean func1Called = false;
  Boolean funcWithArgsCalled = false;

  static Integer getTimesCalled() {
    return ++timesCalled;
  }

  public Map<String, Boolean> selfCheck() {
    results = new HashMap<>();

    results.put("hasFunc1BeenCalled", hasFunc1BeenCalled());

    timesCalled = 0;
    results.put("hasBeenCalledTwice", getTimesCalled() == 2);

    if (!results.containsKey("hasBeenCalledWithArgs")) {
      results.put("hasBeenCalledWithArgs", hasFuncWithArgsBeenCalled(true, "foo"));
    }

    return results;
  }

  public void func1() {
    func1Called = true;
  }

  private boolean hasFunc1BeenCalled() {
    return func1Called;
  }

  public void setFuncWithArgsCalled(Boolean val) {
    funcWithArgsCalled = val;
  }

  private boolean hasFuncWithArgsBeenCalled(Boolean boolArgument, String stringArgument) {
    return funcWithArgsCalled;
  }
}
