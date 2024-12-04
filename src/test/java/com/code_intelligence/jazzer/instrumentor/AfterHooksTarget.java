/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
