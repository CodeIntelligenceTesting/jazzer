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

package com.code_intelligence.jazzer.api;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.InvocationTargetException;
import java.security.SecureRandom;

/** Static helper methods that hooks can use to provide feedback to the fuzzer. */
public final class Jazzer {
  private static final Class<?> JAZZER_INTERNAL;

  private static final MethodHandle ON_FUZZ_TARGET_READY;

  private static final MethodHandle TRACE_STRCMP;
  private static final MethodHandle TRACE_STRSTR;
  private static final MethodHandle TRACE_MEMCMP;
  private static final MethodHandle TRACE_PC_INDIR;

  static {
    Class<?> jazzerInternal = null;
    MethodHandle onFuzzTargetReady = null;
    MethodHandle traceStrcmp = null;
    MethodHandle traceStrstr = null;
    MethodHandle traceMemcmp = null;
    MethodHandle tracePcIndir = null;
    try {
      jazzerInternal = Class.forName("com.code_intelligence.jazzer.runtime.JazzerInternal");
      MethodType onFuzzTargetReadyType = MethodType.methodType(void.class, Runnable.class);
      onFuzzTargetReady =
          MethodHandles.publicLookup()
              .findStatic(
                  jazzerInternal, "registerOnFuzzTargetReadyCallback", onFuzzTargetReadyType);
      Class<?> traceDataFlowNativeCallbacks =
          Class.forName("com.code_intelligence.jazzer.runtime.TraceDataFlowNativeCallbacks");

      // Use method handles for hints as the calls are potentially performance critical.
      MethodType traceStrcmpType =
          MethodType.methodType(void.class, String.class, String.class, int.class, int.class);
      traceStrcmp =
          MethodHandles.publicLookup()
              .findStatic(traceDataFlowNativeCallbacks, "traceStrcmp", traceStrcmpType);
      MethodType traceStrstrType =
          MethodType.methodType(void.class, String.class, String.class, int.class);
      traceStrstr =
          MethodHandles.publicLookup()
              .findStatic(traceDataFlowNativeCallbacks, "traceStrstr", traceStrstrType);
      MethodType traceMemcmpType =
          MethodType.methodType(void.class, byte[].class, byte[].class, int.class, int.class);
      traceMemcmp =
          MethodHandles.publicLookup()
              .findStatic(traceDataFlowNativeCallbacks, "traceMemcmp", traceMemcmpType);
      MethodType tracePcIndirType = MethodType.methodType(void.class, int.class, int.class);
      tracePcIndir =
          MethodHandles.publicLookup()
              .findStatic(traceDataFlowNativeCallbacks, "tracePcIndir", tracePcIndirType);
    } catch (ClassNotFoundException ignore) {
      // Not running in the context of the agent. This is fine as long as no methods are called on
      // this class.
    } catch (NoSuchMethodException | IllegalAccessException e) {
      // This should never happen as the Jazzer API is loaded from the agent and thus should always
      // match the version of the runtime classes.
      System.err.println("ERROR: Incompatible version of the Jazzer API detected, please update.");
      e.printStackTrace();
      System.exit(1);
    }
    JAZZER_INTERNAL = jazzerInternal;
    ON_FUZZ_TARGET_READY = onFuzzTargetReady;
    TRACE_STRCMP = traceStrcmp;
    TRACE_STRSTR = traceStrstr;
    TRACE_MEMCMP = traceMemcmp;
    TRACE_PC_INDIR = tracePcIndir;
  }

  private Jazzer() {}

  /**
   * A 32-bit random number that hooks can use to make pseudo-random choices between multiple
   * possible mutations they could guide the fuzzer towards. Hooks <b>must not</b> base the decision
   * whether or not to report a finding on this number as this will make findings non-reproducible.
   *
   * <p>This is the same number that libFuzzer uses as a seed internally, which makes it possible to
   * deterministically reproduce a previous fuzzing run by supplying the seed value printed by
   * libFuzzer as the value of the {@code -seed}.
   */
  public static final int SEED = getLibFuzzerSeed();

  /**
   * Instructs the fuzzer to guide its mutations towards making {@code current} equal to {@code
   * target}.
   *
   * <p>If the relation between the raw fuzzer input and the value of {@code current} is relatively
   * complex, running the fuzzer with the argument {@code -use_value_profile=1} may be necessary to
   * achieve equality.
   *
   * @param current a non-constant string observed during fuzz target execution
   * @param target a string that {@code current} should become equal to, but currently isn't
   * @param id a (probabilistically) unique identifier for this particular compare hint
   */
  public static void guideTowardsEquality(String current, String target, int id) {
    if (TRACE_STRCMP == null) {
      return;
    }
    try {
      TRACE_STRCMP.invokeExact(current, target, 1, id);
    } catch (Throwable e) {
      e.printStackTrace();
    }
  }

  /**
   * Instructs the fuzzer to guide its mutations towards making {@code current} equal to {@code
   * target}.
   *
   * <p>If the relation between the raw fuzzer input and the value of {@code current} is relatively
   * complex, running the fuzzer with the argument {@code -use_value_profile=1} may be necessary to
   * achieve equality.
   *
   * @param current a non-constant byte array observed during fuzz target execution
   * @param target a byte array that {@code current} should become equal to, but currently isn't
   * @param id a (probabilistically) unique identifier for this particular compare hint
   */
  public static void guideTowardsEquality(byte[] current, byte[] target, int id) {
    if (TRACE_MEMCMP == null) {
      return;
    }
    try {
      TRACE_MEMCMP.invokeExact(current, target, 1, id);
    } catch (Throwable e) {
      e.printStackTrace();
    }
  }

  /**
   * Instructs the fuzzer to guide its mutations towards making {@code haystack} contain {@code
   * needle} as a substring.
   *
   * <p>If the relation between the raw fuzzer input and the value of {@code haystack} is relatively
   * complex, running the fuzzer with the argument {@code -use_value_profile=1} may be necessary to
   * satisfy the substring check.
   *
   * @param haystack a non-constant string observed during fuzz target execution
   * @param needle a string that should be contained in {@code haystack} as a substring, but
   *     currently isn't
   * @param id a (probabilistically) unique identifier for this particular compare hint
   */
  public static void guideTowardsContainment(String haystack, String needle, int id) {
    if (TRACE_STRSTR == null) {
      return;
    }
    try {
      TRACE_STRSTR.invokeExact(haystack, needle, id);
    } catch (Throwable e) {
      e.printStackTrace();
    }
  }

  /**
   * Instructs the fuzzer to attain as many possible values for the absolute value of {@code state}
   * as possible.
   *
   * <p>Call this function from a fuzz target or a hook to help the fuzzer track partial progress
   * (e.g. by passing the length of a common prefix of two lists that should become equal) or
   * explore different values of state that is not directly related to code coverage (see the
   * MazeFuzzer example).
   *
   * <p><b>Note:</b> This hint only takes effect if the fuzzer is run with the argument {@code
   * -use_value_profile=1}.
   *
   * @param state a numeric encoding of a state that should be varied by the fuzzer
   * @param id a (probabilistically) unique identifier for this particular state hint
   */
  public static void exploreState(byte state, int id) {
    if (TRACE_PC_INDIR == null) {
      return;
    }
    // We only use the lower 7 bits of state, which allows for 128 different state values tracked
    // per id. The particular amount of 7 bits of state is also used in libFuzzer's
    // TracePC::HandleCmp:
    // https://github.com/llvm/llvm-project/blob/c12d49c4e286fa108d4d69f1c6d2b8d691993ffd/compiler-rt/lib/fuzzer/FuzzerTracePC.cpp#L390
    // This value should be large enough for most use cases (e.g. tracking the length of a prefix in
    // a comparison) while being small enough that the bitmap isn't filled up too quickly
    // (65536 bits / 128 bits per id = 512 ids).

    // We use tracePcIndir as a way to set a bit in libFuzzer's value profile bitmap. In
    // TracePC::HandleCallerCallee, which is what this function ultimately calls through to, the
    // lower 12 bits of each argument are combined into a 24-bit index into the bitmap, which is
    // then reduced modulo a 16-bit prime. To keep the modulo bias small, we should fill as many
    // of the relevant bits as possible.

    // We pass state in the lowest bits of the caller address, which is used to form the lowest bits
    // of the bitmap index. This should result in the best caching behavior as state is expected to
    // change quickly in consecutive runs and in this way all its bitmap entries would be located
    // close to each other in memory.
    int lowerBits = (state & 0x7f) | (id << 7);
    int upperBits = id >>> 5;
    try {
      TRACE_PC_INDIR.invokeExact(upperBits, lowerBits);
    } catch (Throwable e) {
      e.printStackTrace();
    }
  }

  /**
   * Make Jazzer report the provided {@link Throwable} as a finding.
   *
   * <p><b>Note:</b> This method must only be called from a method hook. In a fuzz target, simply
   * throw an exception to trigger a finding.
   *
   * @param finding the finding that Jazzer should report
   */
  public static void reportFindingFromHook(Throwable finding) {
    try {
      JAZZER_INTERNAL.getMethod("reportFindingFromHook", Throwable.class).invoke(null, finding);
    } catch (NullPointerException | IllegalAccessException | NoSuchMethodException e) {
      // We can only reach this point if the runtime is not on the classpath, e.g. in case of a
      // reproducer. Just throw the finding.
      rethrowUnchecked(finding);
    } catch (InvocationTargetException e) {
      rethrowUnchecked(e.getCause());
    }
  }

  /**
   * Register a callback to be executed right before the fuzz target is executed for the first time.
   *
   * <p>This can be used to disable hooks until after Jazzer has been fully initializing, e.g. to
   * prevent Jazzer internals from triggering hooks on Java standard library classes.
   *
   * @param callback the callback to execute
   */
  public static void onFuzzTargetReady(Runnable callback) {
    try {
      ON_FUZZ_TARGET_READY.invokeExact(callback);
    } catch (Throwable e) {
      e.printStackTrace();
    }
  }

  private static int getLibFuzzerSeed() {
    // The Jazzer driver sets this property based on the value of libFuzzer's -seed command-line
    // option, which allows for fully reproducible fuzzing runs if set. If not running in the
    // context of the driver, fall back to a random number instead.
    String rawSeed = System.getProperty("jazzer.internal.seed");
    if (rawSeed == null) {
      return new SecureRandom().nextInt();
    }
    // If jazzer.internal.seed is set, we expect it to be a valid integer.
    return Integer.parseUnsignedInt(rawSeed);
  }

  // Rethrows a (possibly checked) exception while avoiding a throws declaration.
  @SuppressWarnings("unchecked")
  private static <T extends Throwable> void rethrowUnchecked(Throwable t) throws T {
    throw (T) t;
  }
}
