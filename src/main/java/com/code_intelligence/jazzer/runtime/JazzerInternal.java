/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.runtime;

import java.util.ArrayList;

public final class JazzerInternal {
  public static Throwable lastFinding;

  // The value is only relevant when regression testing. Read by the bytecode emitted by
  // HookMethodVisitor to enable hooks only when invoked from a @FuzzTest.
  //
  // Alternatives considered:
  // Making this thread local rather than global may potentially allow to run fuzz tests in
  // parallel with regular unit tests, but it is next to impossible to determine which thread is
  // currently doing work for a fuzz test versus a regular unit test. Instead, @FuzzTest is
  // annotated with @Isolated.
  @SuppressWarnings("unused")
  public static boolean hooksEnabled = true;

  private static final ArrayList<Runnable> onFuzzTargetReadyCallbacks = new ArrayList<>();

  // Accessed from api.Jazzer via reflection.
  public static void reportFindingFromHook(Throwable finding) {
    lastFinding = finding;
    // Throw an Error that is hard to catch (short of outright ignoring it) in order to quickly
    // terminate the execution of the fuzz target. The finding will be reported as soon as the fuzz
    // target returns even if this Error is swallowed.
    throw new HardToCatchError();
  }

  public static void registerOnFuzzTargetReadyCallback(Runnable callback) {
    onFuzzTargetReadyCallbacks.add(callback);
  }

  public static void onFuzzTargetReady(String fuzzTargetClass) {
    onFuzzTargetReadyCallbacks.forEach(Runnable::run);
    onFuzzTargetReadyCallbacks.clear();
  }
}
