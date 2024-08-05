/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.instrumentor;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

// selfCheck() only passes with the hooks in ReplaceHooks.java applied.
public class ReplaceHooksTarget implements ReplaceHooksTargetContract {
  Map<String, Boolean> results = new HashMap<>();

  public static boolean shouldReturnTrue3() {
    // return true;
    return false;
  }

  public Map<String, Boolean> selfCheck() {
    results = new HashMap<>();

    results.put("shouldReturnTrue1", shouldReturnTrue1());
    results.put("shouldReturnTrue2", shouldReturnTrue2());
    results.put("shouldReturnTrue3", shouldReturnTrue3());
    try {
      boolean notTrue = false;
      results.put("shouldReturnFalse1", notTrue);
      if (!results.get("shouldReturnFalse1"))
        results.put("shouldReturnFalse1", !shouldReturnFalse1());
      boolean notFalse = true;
      results.put("shouldReturnFalse2", !shouldReturnFalse2() && notFalse);
      results.put("shouldReturnFalse3", !shouldReturnFalse3());
    } catch (Exception e) {
      boolean notTrue = false;
      results.put("shouldNotBeExecuted", notTrue);
    }
    results.put("shouldReturnReversed", shouldReturnReversed("foo").equals("oof"));
    results.put("shouldIncrement", shouldIncrement(5) == 6);
    results.put("verifyIdentity", verifyIdentity());

    results.put("shouldCallPass", false);
    if (!results.get("shouldCallPass")) {
      shouldCallPass();
    }

    ArrayList<Boolean> boolList = new ArrayList<>();
    boolList.add(false);
    results.put("arrayListGet", boolList.get(0));

    HashSet<Boolean> boolSet = new HashSet<>();
    results.put("stringSetGet", boolSet.contains(Boolean.TRUE));

    results.put("shouldInitialize", new ReplaceHooksInit().initialized);
    results.put("shouldInitializeWithParams", new ReplaceHooksInit(false, "foo").initialized);

    return results;
  }

  public boolean shouldReturnTrue1() {
    // return true;
    return false;
  }

  public boolean shouldReturnTrue2() {
    // return true;
    return false;
  }

  protected Boolean shouldReturnFalse1() {
    // return false;
    return true;
  }

  Boolean shouldReturnFalse2() {
    // return false;
    return true;
  }

  public Boolean shouldReturnFalse3() {
    // return false;
    return true;
  }

  public String shouldReturnReversed(String input) {
    // return new StringBuilder(input).reverse().toString();
    return input;
  }

  public int shouldIncrement(int input) {
    // return input + 1;
    return input;
  }

  private void shouldCallPass() {
    // pass("shouldCallPass");
  }

  private boolean verifyIdentity() {
    SecureRandom rand = new SecureRandom();
    int input = rand.nextInt();
    // return idempotent(idempotent(input)) == input;
    return idempotent(input) == input;
  }

  private int idempotent(int input) {
    int secret = 0x12345678;
    return input ^ secret;
  }

  public void pass(String test) {
    results.put(test, true);
  }
}
