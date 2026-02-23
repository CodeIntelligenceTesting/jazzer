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
import java.util.concurrent.ConcurrentHashMap;

/** Static helper methods that hooks can use to provide feedback to the fuzzer. */
public final class Jazzer {
  private static final Class<?> JAZZER_INTERNAL;

  private static final MethodHandle ON_FUZZ_TARGET_READY;

  private static final MethodHandle TRACE_STRCMP;
  private static final MethodHandle TRACE_STRSTR;
  private static final MethodHandle TRACE_MEMCMP;

  private static final MethodHandle COUNTERS_TRACKER_ALLOCATE;
  private static final MethodHandle COUNTERS_TRACKER_SET_RANGE;
  private static final MethodHandle COUNTERS_TRACKER_SET_COUNTER;

  private static final byte[] EXPLORE_BUCKET_VALUES = {1, 2, 3, 4, 8, 16, 32, (byte) 128};

  /**
   * Default number of counters allocated for each call site of a method that requires registering a
   * range of artificial coverage counters, e.g., Jazzer maximize API. The user's value range is
   * linearly mapped onto this many counters.
   */
  public static final int DEFAULT_NUM_COUNTERS = 1024;

  /** Tracks the registered minValue and maxValue per maximize call-site id. */
  private static final ConcurrentHashMap<Integer, long[]> idToRange = new ConcurrentHashMap<>();

  static {
    Class<?> jazzerInternal = null;
    MethodHandle onFuzzTargetReady = null;
    MethodHandle traceStrcmp = null;
    MethodHandle traceStrstr = null;
    MethodHandle traceMemcmp = null;
    MethodHandle countersTrackerAllocate = null;
    MethodHandle countersTrackerSetRange = null;
    MethodHandle countersTrackerSetCounter = null;
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

      Class<?> countersTracker =
          Class.forName("com.code_intelligence.jazzer.runtime.ExtraCountersTracker");
      MethodType allocateType = MethodType.methodType(void.class, int.class, int.class);
      countersTrackerAllocate =
          MethodHandles.publicLookup()
              .findStatic(countersTracker, "ensureCountersAllocated", allocateType);
      MethodType setRangeType = MethodType.methodType(void.class, int.class, int.class);
      countersTrackerSetRange =
          MethodHandles.publicLookup().findStatic(countersTracker, "setCounterRange", setRangeType);
      MethodType setCounterType =
          MethodType.methodType(void.class, int.class, int.class, byte.class);
      countersTrackerSetCounter =
          MethodHandles.publicLookup().findStatic(countersTracker, "setCounter", setCounterType);
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
    COUNTERS_TRACKER_ALLOCATE = countersTrackerAllocate;
    COUNTERS_TRACKER_SET_RANGE = countersTrackerSetRange;
    COUNTERS_TRACKER_SET_COUNTER = countersTrackerSetCounter;
  }

  private Jazzer() {}

  /**
   * A 32-bit random number that hooks can use to make pseudo-random choices between multiple
   * possible mutations they could guide the fuzzer towards. Hooks <b>must not</b> base the decision
   * whether to report a finding on this number as this will make findings non-reproducible.
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
    } catch (JazzerApiException e) {
      throw e;
    } catch (Throwable e) {
      throw new JazzerApiException("guideTowardsEquality: " + e.getMessage(), e);
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
    } catch (JazzerApiException e) {
      throw e;
    } catch (Throwable e) {
      throw new JazzerApiException("guideTowardsEquality: " + e.getMessage(), e);
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
    } catch (JazzerApiException e) {
      throw e;
    } catch (Throwable e) {
      throw new JazzerApiException("guideTowardsContainment: " + e.getMessage(), e);
    }
  }

  /**
   * Instructs the fuzzer to attain as many possible values for {@code state} as possible.
   *
   * <p>Call this function from a fuzz target or a hook to help the fuzzer track partial progress
   * (e.g. by passing the length of a common prefix of two lists that should become equal) or
   * explore different values of state that is not directly related to code coverage (see the
   * MazeFuzzer example).
   *
   * <p>Each unique state value is tracked via libFuzzer's counter bucketing mechanism, enabling us
   * to represent 8 different states for each coverage counter. As a result, all 256 byte values are
   * distinguished by mapping each to a unique (counter, bucket) pair across 32 counters. See:
   * https://github.com/llvm/llvm-project/blob/972e73b812cb7b6dd349c7c07daae73314f29e8f/compiler-rt/lib/fuzzer/FuzzerTracePC.h#L213-L235
   *
   * @param state a numeric encoding of a state that should be varied by the fuzzer
   * @param id a (probabilistically) unique identifier for this particular state hint
   */
  public static void exploreState(byte state, int id) {
    if (COUNTERS_TRACKER_ALLOCATE == null) {
      return;
    }
    try {
      COUNTERS_TRACKER_ALLOCATE.invokeExact(id, 32);
      int unsignedState = state & 0xff;
      int counterIndex = unsignedState >> 3;
      byte counterValue = EXPLORE_BUCKET_VALUES[unsignedState & 0x7];
      COUNTERS_TRACKER_SET_COUNTER.invokeExact(id, counterIndex, counterValue);
    } catch (Throwable e) {
      throw new JazzerApiException("exploreState: " + e.getMessage(), e);
    }
  }

  /**
   * Convenience overload of {@link #exploreState(byte, int)} that allows using automatically
   * generated call-site identifiers. During instrumentation, calls to this method are replaced with
   * calls to {@link #exploreState(byte, int)} using a unique id for each call site.
   *
   * <p>Without instrumentation, this is a no-op.
   *
   * @param state a numeric encoding of a state that should be varied by the fuzzer
   * @see #exploreState(byte, int)
   */
  public static void exploreState(byte state) {
    // Instrumentation replaces calls to this method with calls to exploreState(byte, int) using
    // an automatically generated call-site id. Without instrumentation, this is a no-op.
  }

  /**
   * Core implementation of the hill-climbing maximize API. It maps {@code value} from the range
   * [{@code minValue}, {@code maxValue}] onto {@code numCounters} coverage counters via linear
   * interpolation, then sets all counters from 0 to the mapped offset.
   *
   * <p>Values below {@code minValue} produce no signal. Values above {@code maxValue} are clamped.
   *
   * <p>Must be invoked with the same {@code minValue}, {@code maxValue}, and {@code numCounters}
   * for a given {@code id} across all calls. Passing different values is illegal.
   *
   * @param value the value to maximize
   * @param minValue the minimum expected value (inclusive)
   * @param maxValue the maximum expected value (inclusive); must be &gt;= {@code minValue}
   * @param numCounters the number of counters to allocate; must be &gt; 0
   * @param id a unique identifier for this call site (must be consistent across runs)
   * @throws JazzerApiException if {@code maxValue < minValue} or {@code numCounters <= 0}
   */
  public static void maximize(long value, long minValue, long maxValue, int numCounters, int id) {
    if (COUNTERS_TRACKER_ALLOCATE == null) {
      return;
    }

    try {
      ensureRangeConsistent(id, minValue, maxValue);
      int effectiveCounters = effectiveCounters(minValue, maxValue, numCounters);
      COUNTERS_TRACKER_ALLOCATE.invokeExact(id, effectiveCounters);

      if (value >= minValue) {
        int toOffset;
        if (minValue == maxValue) {
          toOffset = 0;
        } else {
          double range = (double) maxValue - (double) minValue;
          double offset = (double) Math.min(value, maxValue) - (double) minValue;
          toOffset = (int) (offset / range * (effectiveCounters - 1));
        }
        COUNTERS_TRACKER_SET_RANGE.invokeExact(id, toOffset);
      }
    } catch (JazzerApiException e) {
      throw e;
    } catch (Throwable e) {
      throw new JazzerApiException("maximize: " + e.getMessage(), e);
    }
  }

  private static void ensureRangeConsistent(int id, long minValue, long maxValue) {
    long[] existing = idToRange.putIfAbsent(id, new long[] {minValue, maxValue});
    if (existing != null && (existing[0] != minValue || existing[1] != maxValue)) {
      throw new IllegalArgumentException(
          String.format(
              "Range for id %d must remain constant across calls. "
                  + "Expected [%d, %d], but got [%d, %d].",
              id, existing[0], existing[1], minValue, maxValue));
    }
  }

  private static int effectiveCounters(long minValue, long maxValue, int maxNumCounters) {
    if (maxValue < minValue) {
      throw new IllegalArgumentException(
          "maxValue (" + maxValue + ") must not be less than minValue (" + minValue + ")");
    }
    if (maxNumCounters <= 0) {
      throw new IllegalArgumentException(
          "maxNumCounters (" + maxNumCounters + ") must be positive");
    }

    // Cap maxNumCounters at the actual range size to avoid wasting counters when the
    // range is smaller than the requested number (e.g. range [0, 10] only needs 11).
    double rangeSize = (double) maxValue - (double) minValue + 1;
    return (rangeSize < maxNumCounters) ? (int) rangeSize : maxNumCounters;
  }

  /**
   * Convenience overload of {@link #maximize(long, long, long, int, int)} that uses {@link
   * #DEFAULT_NUM_COUNTERS} counters and an automatically generated call-site id.
   *
   * <p>During instrumentation, calls to this method are replaced by a hook that supplies a unique
   * id for each call site. Without instrumentation, this is a no-op.
   *
   * <pre>{@code
   * // Maximize temperature in [0, 4500]
   * Jazzer.maximize(temperature, 0, 4500);
   * }</pre>
   *
   * @param value the value to maximize
   * @param minValue the minimum expected value (inclusive)
   * @param maxValue the maximum expected value (inclusive)
   * @see #maximize(long, long, long, int, int)
   */
  public static void maximize(long value, long minValue, long maxValue) {
    // Instrumentation replaces calls to this method with the core overload using
    // DEFAULT_NUM_COUNTERS and an automatically generated call-site id.
    // Without instrumentation, this is a no-op.
  }

  /**
   * Convenience overload of {@link #maximize(long, long, long, int, int)} that uses a custom number
   * of counters and an automatically generated call-site id.
   *
   * <p>During instrumentation, calls to this method are replaced by a hook that supplies a unique
   * id for each call site. Without instrumentation, this is a no-op.
   *
   * @param value the value to maximize
   * @param minValue the minimum expected value (inclusive)
   * @param maxValue the maximum expected value (inclusive)
   * @param numCounters the number of counters to allocate; must be &gt; 0
   * @see #maximize(long, long, long, int, int)
   */
  public static void maximize(long value, long minValue, long maxValue, int numCounters) {
    // Instrumentation replaces calls to this method with the core overload using
    // the given numCounters and an automatically generated call-site id.
    // Without instrumentation, this is a no-op.
  }

  /**
   * Core implementation of the hill-climbing minimize API. It maps {@code value} from the range
   * [{@code minValue}, {@code maxValue}] onto {@code numCounters} coverage counters via inverse
   * linear interpolation, then sets all counters from 0 to the mapped offset.
   *
   * <p>Lower values produce more signal (more counters set), which causes the fuzzer to prefer
   * inputs that result in lower values. Values above {@code maxValue} produce no signal. Values
   * below {@code minValue} are clamped.
   *
   * <p>Must be invoked with the same {@code minValue}, {@code maxValue}, and {@code numCounters}
   * for a given {@code id} across all calls. Passing different values is illegal.
   *
   * @param value the value to minimize
   * @param minValue the minimum expected value (inclusive)
   * @param maxValue the maximum expected value (inclusive); must be &gt;= {@code minValue}
   * @param numCounters the number of counters to allocate; must be &gt; 0
   * @param id a unique identifier for this call site (must be consistent across runs)
   * @throws JazzerApiException if {@code maxValue < minValue} or {@code numCounters <= 0}
   */
  public static void minimize(long value, long minValue, long maxValue, int numCounters, int id) {
    if (COUNTERS_TRACKER_ALLOCATE == null) {
      return;
    }

    try {
      ensureRangeConsistent(id, minValue, maxValue);
      int effectiveCounters = effectiveCounters(minValue, maxValue, numCounters);
      COUNTERS_TRACKER_ALLOCATE.invokeExact(id, effectiveCounters);

      if (value <= maxValue) {
        int toOffset;
        if (minValue == maxValue) {
          toOffset = 0;
        } else {
          double range = (double) maxValue - (double) minValue;
          double offset = (double) maxValue - (double) Math.max(value, minValue);
          toOffset = (int) (offset / range * (effectiveCounters - 1));
        }
        COUNTERS_TRACKER_SET_RANGE.invokeExact(id, toOffset);
      }
    } catch (JazzerApiException e) {
      throw e;
    } catch (Throwable e) {
      throw new JazzerApiException("minimize: " + e.getMessage(), e);
    }
  }

  /**
   * Convenience overload of {@link #minimize(long, long, long, int, int)} that uses {@link
   * #DEFAULT_NUM_COUNTERS} counters and an automatically generated call-site id.
   *
   * <p>During instrumentation, calls to this method are replaced by a hook that supplies a unique
   * id for each call site. Without instrumentation, this is a no-op.
   *
   * <pre>{@code
   * // Minimize temperature in [0, 4000]
   * Jazzer.minimize(temperature, 0, 4000);
   * }</pre>
   *
   * @param value the value to minimize
   * @param minValue the minimum expected value (inclusive)
   * @param maxValue the maximum expected value (inclusive)
   * @see #minimize(long, long, long, int, int)
   */
  public static void minimize(long value, long minValue, long maxValue) {
    // Instrumentation replaces calls to this method with the core overload using
    // DEFAULT_NUM_COUNTERS and an automatically generated call-site id.
    // Without instrumentation, this is a no-op.
  }

  /**
   * Convenience overload of {@link #minimize(long, long, long, int, int)} that uses a custom number
   * of counters and an automatically generated call-site id.
   *
   * <p>During instrumentation, calls to this method are replaced by a hook that supplies a unique
   * id for each call site. Without instrumentation, this is a no-op.
   *
   * @param value the value to minimize
   * @param minValue the minimum expected value (inclusive)
   * @param maxValue the maximum expected value (inclusive)
   * @param numCounters the number of counters to allocate; must be &gt; 0
   * @see #minimize(long, long, long, int, int)
   */
  public static void minimize(long value, long minValue, long maxValue, int numCounters) {
    // Instrumentation replaces calls to this method with the core overload using
    // the given numCounters and an automatically generated call-site id.
    // Without instrumentation, this is a no-op.
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
    } catch (JazzerApiException e) {
      throw e;
    } catch (Throwable e) {
      throw new JazzerApiException("onFuzzTargetReady: " + e.getMessage(), e);
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
