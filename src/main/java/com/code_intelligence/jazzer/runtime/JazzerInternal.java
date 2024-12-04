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
