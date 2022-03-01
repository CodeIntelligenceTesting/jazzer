// Copyright 2021 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.code_intelligence.jazzer.api;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.InvocationTargetException;
import java.security.SecureRandom;

/**
 * Helper class with static methods that interact with Jazzer at runtime.
 */
final public class Jazzer {
  /**
   * A 32-bit random number that hooks can use to make pseudo-random choices
   * between multiple possible mutations they could guide the fuzzer towards.
   * Hooks <b>must not</b> base the decision whether or not to report a finding
   * on this number as this will make findings non-reproducible.
   *
   * This is the same number that libFuzzer uses as a seed internally, which
   * makes it possible to deterministically reproduce a previous fuzzing run by
   * supplying the seed value printed by libFuzzer as the value of the
   * {@code -seed}.
   */
  public static final int SEED = getLibFuzzerSeed();

  private static final Class<?> JAZZER_INTERNAL;

  private static final MethodHandle ON_FUZZ_TARGET_READY;

  private static final MethodHandle TRACE_STRCMP;
  private static final MethodHandle TRACE_STRSTR;
  private static final MethodHandle TRACE_MEMCMP;
  private static final MethodHandle TRACE_PC_INDIR;

  private static final MethodHandle CONSUME;
  private static final MethodHandle AUTOFUZZ_FUNCTION_1;
  private static final MethodHandle AUTOFUZZ_FUNCTION_2;
  private static final MethodHandle AUTOFUZZ_FUNCTION_3;
  private static final MethodHandle AUTOFUZZ_FUNCTION_4;
  private static final MethodHandle AUTOFUZZ_FUNCTION_5;
  private static final MethodHandle AUTOFUZZ_CONSUMER_1;
  private static final MethodHandle AUTOFUZZ_CONSUMER_2;
  private static final MethodHandle AUTOFUZZ_CONSUMER_3;
  private static final MethodHandle AUTOFUZZ_CONSUMER_4;
  private static final MethodHandle AUTOFUZZ_CONSUMER_5;

  static {
    Class<?> jazzerInternal = null;
    MethodHandle onFuzzTargetReady = null;
    MethodHandle traceStrcmp = null;
    MethodHandle traceStrstr = null;
    MethodHandle traceMemcmp = null;
    MethodHandle tracePcIndir = null;
    MethodHandle consume = null;
    MethodHandle autofuzzFunction1 = null;
    MethodHandle autofuzzFunction2 = null;
    MethodHandle autofuzzFunction3 = null;
    MethodHandle autofuzzFunction4 = null;
    MethodHandle autofuzzFunction5 = null;
    MethodHandle autofuzzConsumer1 = null;
    MethodHandle autofuzzConsumer2 = null;
    MethodHandle autofuzzConsumer3 = null;
    MethodHandle autofuzzConsumer4 = null;
    MethodHandle autofuzzConsumer5 = null;
    try {
      jazzerInternal = Class.forName("com.code_intelligence.jazzer.runtime.JazzerInternal");
      MethodType onFuzzTargetReadyType = MethodType.methodType(void.class, Runnable.class);
      onFuzzTargetReady = MethodHandles.publicLookup().findStatic(
          jazzerInternal, "registerOnFuzzTargetReadyCallback", onFuzzTargetReadyType);
      Class<?> traceDataFlowNativeCallbacks =
          Class.forName("com.code_intelligence.jazzer.runtime.TraceDataFlowNativeCallbacks");

      // Use method handles for hints as the calls are potentially performance critical.
      MethodType traceStrcmpType =
          MethodType.methodType(void.class, String.class, String.class, int.class, int.class);
      traceStrcmp = MethodHandles.publicLookup().findStatic(
          traceDataFlowNativeCallbacks, "traceStrcmp", traceStrcmpType);
      MethodType traceStrstrType =
          MethodType.methodType(void.class, String.class, String.class, int.class);
      traceStrstr = MethodHandles.publicLookup().findStatic(
          traceDataFlowNativeCallbacks, "traceStrstr", traceStrstrType);
      MethodType traceMemcmpType =
          MethodType.methodType(void.class, byte[].class, byte[].class, int.class, int.class);
      traceMemcmp = MethodHandles.publicLookup().findStatic(
          traceDataFlowNativeCallbacks, "traceMemcmp", traceMemcmpType);
      MethodType tracePcIndirType = MethodType.methodType(void.class, int.class, int.class);
      tracePcIndir = MethodHandles.publicLookup().findStatic(
          traceDataFlowNativeCallbacks, "tracePcIndir", tracePcIndirType);

      Class<?> metaClass = Class.forName("com.code_intelligence.jazzer.autofuzz.Meta");
      MethodType consumeType =
          MethodType.methodType(Object.class, FuzzedDataProvider.class, Class.class);
      consume = MethodHandles.publicLookup().findStatic(metaClass, "consume", consumeType);

      autofuzzFunction1 = MethodHandles.publicLookup().findStatic(metaClass, "autofuzz",
          MethodType.methodType(Object.class, FuzzedDataProvider.class, Function1.class));
      autofuzzFunction2 = MethodHandles.publicLookup().findStatic(metaClass, "autofuzz",
          MethodType.methodType(Object.class, FuzzedDataProvider.class, Function2.class));
      autofuzzFunction3 = MethodHandles.publicLookup().findStatic(metaClass, "autofuzz",
          MethodType.methodType(Object.class, FuzzedDataProvider.class, Function3.class));
      autofuzzFunction4 = MethodHandles.publicLookup().findStatic(metaClass, "autofuzz",
          MethodType.methodType(Object.class, FuzzedDataProvider.class, Function4.class));
      autofuzzFunction5 = MethodHandles.publicLookup().findStatic(metaClass, "autofuzz",
          MethodType.methodType(Object.class, FuzzedDataProvider.class, Function5.class));
      autofuzzConsumer1 = MethodHandles.publicLookup().findStatic(metaClass, "autofuzz",
          MethodType.methodType(void.class, FuzzedDataProvider.class, Consumer1.class));
      autofuzzConsumer2 = MethodHandles.publicLookup().findStatic(metaClass, "autofuzz",
          MethodType.methodType(void.class, FuzzedDataProvider.class, Consumer2.class));
      autofuzzConsumer3 = MethodHandles.publicLookup().findStatic(metaClass, "autofuzz",
          MethodType.methodType(void.class, FuzzedDataProvider.class, Consumer3.class));
      autofuzzConsumer4 = MethodHandles.publicLookup().findStatic(metaClass, "autofuzz",
          MethodType.methodType(void.class, FuzzedDataProvider.class, Consumer4.class));
      autofuzzConsumer5 = MethodHandles.publicLookup().findStatic(metaClass, "autofuzz",
          MethodType.methodType(void.class, FuzzedDataProvider.class, Consumer5.class));
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
    CONSUME = consume;
    AUTOFUZZ_FUNCTION_1 = autofuzzFunction1;
    AUTOFUZZ_FUNCTION_2 = autofuzzFunction2;
    AUTOFUZZ_FUNCTION_3 = autofuzzFunction3;
    AUTOFUZZ_FUNCTION_4 = autofuzzFunction4;
    AUTOFUZZ_FUNCTION_5 = autofuzzFunction5;
    AUTOFUZZ_CONSUMER_1 = autofuzzConsumer1;
    AUTOFUZZ_CONSUMER_2 = autofuzzConsumer2;
    AUTOFUZZ_CONSUMER_3 = autofuzzConsumer3;
    AUTOFUZZ_CONSUMER_4 = autofuzzConsumer4;
    AUTOFUZZ_CONSUMER_5 = autofuzzConsumer5;
  }

  private Jazzer() {}

  /**
   * Attempts to invoke {@code func} with arguments created automatically from the fuzzer input
   * using only public methods available on the classpath.
   *
   * <b>Note:</b> This function is inherently heuristic and may fail to execute {@code func} in
   * meaningful ways for a number of reasons.
   *
   * @param data the {@link FuzzedDataProvider} instance provided to {@code fuzzerTestOneInput}.
   * @param func a method reference for the function to autofuzz. If there are multiple overloads,
   *     resolve ambiguities by explicitly casting to {@link Function1} with (partially) specified
   *     type variables, e.g. {@code (Function1<String, ?>) String::new}.
   * @return the return value of {@code func}, or {@code null} if {@code autofuzz} failed to invoke
   *     the function.
   * @throws Throwable any {@link Throwable} thrown by {@code func}, or an {@link
   *     AutofuzzConstructionException} if autofuzz failed to construct the arguments for the call.
   *     The {@link Throwable} is thrown unchecked.
   */
  @SuppressWarnings("unchecked")
  public static <T1, R> R autofuzz(FuzzedDataProvider data, Function1<T1, R> func) {
    try {
      return (R) AUTOFUZZ_FUNCTION_1.invoke(data, func);
    } catch (AutofuzzInvocationException e) {
      rethrowUnchecked(e.getCause());
    } catch (Throwable t) {
      rethrowUnchecked(t);
    }
    // Not reached.
    return null;
  }

  /**
   * Attempts to invoke {@code func} with arguments created automatically from the fuzzer input
   * using only public methods available on the classpath.
   *
   * <b>Note:</b> This function is inherently heuristic and may fail to execute {@code func} in
   * meaningful ways for a number of reasons.
   *
   * @param data the {@link FuzzedDataProvider} instance provided to {@code fuzzerTestOneInput}.
   * @param func a method reference for the function to autofuzz. If there are multiple overloads,
   *     resolve ambiguities by explicitly casting to {@link Function2} with (partially) specified
   *     type variables.
   * @return the return value of {@code func}, or {@code null} if {@code autofuzz} failed to invoke
   *     the function.
   * @throws Throwable any {@link Throwable} thrown by {@code func}, or an {@link
   *     AutofuzzConstructionException} if autofuzz failed to construct the arguments for the call.
   *     The {@link Throwable} is thrown unchecked.
   */
  @SuppressWarnings("unchecked")
  public static <T1, T2, R> R autofuzz(FuzzedDataProvider data, Function2<T1, T2, R> func) {
    try {
      return (R) AUTOFUZZ_FUNCTION_2.invoke(data, func);
    } catch (AutofuzzInvocationException e) {
      rethrowUnchecked(e.getCause());
    } catch (Throwable t) {
      rethrowUnchecked(t);
    }
    // Not reached.
    return null;
  }

  /**
   * Attempts to invoke {@code func} with arguments created automatically from the fuzzer input
   * using only public methods available on the classpath.
   *
   * <b>Note:</b> This function is inherently heuristic and may fail to execute {@code func} in
   * meaningful ways for a number of reasons.
   *
   * @param data the {@link FuzzedDataProvider} instance provided to {@code fuzzerTestOneInput}.
   * @param func a method reference for the function to autofuzz. If there are multiple overloads,
   *     resolve ambiguities by explicitly casting to {@link Function3} with (partially) specified
   *     type variables.
   * @return the return value of {@code func}, or {@code null} if {@code autofuzz} failed to invoke
   *     the function.
   * @throws Throwable any {@link Throwable} thrown by {@code func}, or an {@link
   *     AutofuzzConstructionException} if autofuzz failed to construct the arguments for the call.
   *     The {@link Throwable} is thrown unchecked.
   */
  @SuppressWarnings("unchecked")
  public static <T1, T2, T3, R> R autofuzz(FuzzedDataProvider data, Function3<T1, T2, T3, R> func) {
    try {
      return (R) AUTOFUZZ_FUNCTION_3.invoke(data, func);
    } catch (AutofuzzInvocationException e) {
      rethrowUnchecked(e.getCause());
    } catch (Throwable t) {
      rethrowUnchecked(t);
    }
    // Not reached.
    return null;
  }

  /**
   * Attempts to invoke {@code func} with arguments created automatically from the fuzzer input
   * using only public methods available on the classpath.
   *
   * <b>Note:</b> This function is inherently heuristic and may fail to execute {@code func} in
   * meaningful ways for a number of reasons.
   *
   * @param data the {@link FuzzedDataProvider} instance provided to {@code fuzzerTestOneInput}.
   * @param func a method reference for the function to autofuzz. If there are multiple overloads,
   *     resolve ambiguities by explicitly casting to {@link Function4} with (partially) specified
   *     type variables.
   * @return the return value of {@code func}, or {@code null} if {@code autofuzz} failed to invoke
   *     the function.
   * @throws Throwable any {@link Throwable} thrown by {@code func}, or an {@link
   *     AutofuzzConstructionException} if autofuzz failed to construct the arguments for the call.
   *     The {@link Throwable} is thrown unchecked.
   */
  @SuppressWarnings("unchecked")
  public static <T1, T2, T3, T4, R> R autofuzz(
      FuzzedDataProvider data, Function4<T1, T2, T3, T4, R> func) {
    try {
      return (R) AUTOFUZZ_FUNCTION_4.invoke(data, func);
    } catch (AutofuzzInvocationException e) {
      rethrowUnchecked(e.getCause());
    } catch (Throwable t) {
      rethrowUnchecked(t);
    }
    // Not reached.
    return null;
  }

  /**
   * Attempts to invoke {@code func} with arguments created automatically from the fuzzer input
   * using only public methods available on the classpath.
   *
   * <b>Note:</b> This function is inherently heuristic and may fail to execute {@code func} in
   * meaningful ways for a number of reasons.
   *
   * @param data the {@link FuzzedDataProvider} instance provided to {@code fuzzerTestOneInput}.
   * @param func a method reference for the function to autofuzz. If there are multiple overloads,
   *     resolve ambiguities by explicitly casting to {@link Function5} with (partially) specified
   *     type variables.
   * @return the return value of {@code func}, or {@code null} if {@code autofuzz} failed to invoke
   *     the function.
   * @throws Throwable any {@link Throwable} thrown by {@code func}, or an {@link
   *     AutofuzzConstructionException} if autofuzz failed to construct the arguments for the call.
   *     The {@link Throwable} is thrown unchecked.
   */
  @SuppressWarnings("unchecked")
  public static <T1, T2, T3, T4, T5, R> R autofuzz(
      FuzzedDataProvider data, Function5<T1, T2, T3, T4, T5, R> func) {
    try {
      return (R) AUTOFUZZ_FUNCTION_5.invoke(data, func);
    } catch (AutofuzzInvocationException e) {
      rethrowUnchecked(e.getCause());
    } catch (Throwable t) {
      rethrowUnchecked(t);
    }
    // Not reached.
    return null;
  }

  /**
   * Attempts to invoke {@code func} with arguments created automatically from the fuzzer input
   * using only public methods available on the classpath.
   *
   * <b>Note:</b> This function is inherently heuristic and may fail to execute {@code func} in
   * meaningful ways for a number of reasons.
   *
   * @param data the {@link FuzzedDataProvider} instance provided to {@code fuzzerTestOneInput}.
   * @param func a method reference for the function to autofuzz. If there are multiple overloads,
   *     resolve ambiguities by explicitly casting to {@link Consumer1} with explicitly specified
   * type variable.
   * @throws Throwable any {@link Throwable} thrown by {@code func}, or an {@link
   *     AutofuzzConstructionException} if autofuzz failed to construct the arguments for the call.
   *     The {@link Throwable} is thrown unchecked.
   */
  public static <T1> void autofuzz(FuzzedDataProvider data, Consumer1<T1> func) {
    try {
      AUTOFUZZ_CONSUMER_1.invoke(data, func);
    } catch (AutofuzzInvocationException e) {
      rethrowUnchecked(e.getCause());
    } catch (Throwable t) {
      rethrowUnchecked(t);
    }
  }

  /**
   * Attempts to invoke {@code func} with arguments created automatically from the fuzzer input
   * using only public methods available on the classpath.
   *
   * <b>Note:</b> This function is inherently heuristic and may fail to execute {@code func} in
   * meaningful ways for a number of reasons.
   *
   * @param data the {@link FuzzedDataProvider} instance provided to {@code fuzzerTestOneInput}.
   * @param func a method reference for the function to autofuzz. If there are multiple overloads,
   *     resolve ambiguities by explicitly casting to {@link Consumer2} with (partially) specified
   * type variables.
   * @throws Throwable any {@link Throwable} thrown by {@code func}, or an {@link
   *     AutofuzzConstructionException} if autofuzz failed to construct the arguments for the call.
   *     The {@link Throwable} is thrown unchecked.
   */
  public static <T1, T2> void autofuzz(FuzzedDataProvider data, Consumer2<T1, T2> func) {
    try {
      AUTOFUZZ_CONSUMER_2.invoke(data, func);
    } catch (AutofuzzInvocationException e) {
      rethrowUnchecked(e.getCause());
    } catch (Throwable t) {
      rethrowUnchecked(t);
    }
  }

  /**
   * Attempts to invoke {@code func} with arguments created automatically from the fuzzer input
   * using only public methods available on the classpath.
   *
   * <b>Note:</b> This function is inherently heuristic and may fail to execute {@code func} in
   * meaningful ways for a number of reasons.
   *
   * @param data the {@link FuzzedDataProvider} instance provided to {@code fuzzerTestOneInput}.
   * @param func a method reference for the function to autofuzz. If there are multiple overloads,
   *     resolve ambiguities by explicitly casting to {@link Consumer3} with (partially) specified
   * type variables.
   * @throws Throwable any {@link Throwable} thrown by {@code func}, or an {@link
   *     AutofuzzConstructionException} if autofuzz failed to construct the arguments for the call.
   *     The {@link Throwable} is thrown unchecked.
   */
  public static <T1, T2, T3> void autofuzz(FuzzedDataProvider data, Consumer3<T1, T2, T3> func) {
    try {
      AUTOFUZZ_CONSUMER_3.invoke(data, func);
    } catch (AutofuzzInvocationException e) {
      rethrowUnchecked(e.getCause());
    } catch (Throwable t) {
      rethrowUnchecked(t);
    }
  }

  /**
   * Attempts to invoke {@code func} with arguments created automatically from the fuzzer input
   * using only public methods available on the classpath.
   *
   * <b>Note:</b> This function is inherently heuristic and may fail to execute {@code func} in
   * meaningful ways for a number of reasons.
   *
   * @param data the {@link FuzzedDataProvider} instance provided to {@code fuzzerTestOneInput}.
   * @param func a method reference for the function to autofuzz. If there are multiple overloads,
   *     resolve ambiguities by explicitly casting to {@link Consumer4} with (partially) specified
   * type variables.
   * @throws Throwable any {@link Throwable} thrown by {@code func}, or an {@link
   *     AutofuzzConstructionException} if autofuzz failed to construct the arguments for the call.
   *     The {@link Throwable} is thrown unchecked.
   */
  public static <T1, T2, T3, T4> void autofuzz(
      FuzzedDataProvider data, Consumer4<T1, T2, T3, T4> func) {
    try {
      AUTOFUZZ_CONSUMER_4.invoke(data, func);
    } catch (AutofuzzInvocationException e) {
      rethrowUnchecked(e.getCause());
    } catch (Throwable t) {
      rethrowUnchecked(t);
    }
  }

  /**
   * Attempts to invoke {@code func} with arguments created automatically from the fuzzer input
   * using only public methods available on the classpath.
   *
   * <b>Note:</b> This function is inherently heuristic and may fail to execute {@code func} in
   * meaningful ways for a number of reasons.
   *
   * @param data the {@link FuzzedDataProvider} instance provided to {@code fuzzerTestOneInput}.
   * @param func a method reference for the function to autofuzz. If there are multiple overloads,
   *     resolve ambiguities by explicitly casting to {@link Consumer5} with (partially) specified
   * type variables.
   * @throws Throwable any {@link Throwable} thrown by {@code func}, or an {@link
   *     AutofuzzConstructionException} if autofuzz failed to construct the arguments for the call.
   *     The {@link Throwable} is thrown unchecked.
   */
  public static <T1, T2, T3, T4, T5> void autofuzz(
      FuzzedDataProvider data, Consumer5<T1, T2, T3, T4, T5> func) {
    try {
      AUTOFUZZ_CONSUMER_5.invoke(data, func);
    } catch (AutofuzzInvocationException e) {
      rethrowUnchecked(e.getCause());
    } catch (Throwable t) {
      rethrowUnchecked(t);
    }
  }

  /**
   * Attempts to construct an instance of {@code type} from the fuzzer input using only public
   * methods available on the classpath.
   *
   * <b>Note:</b> This function is inherently heuristic and may fail to return meaningful values for
   * a variety of reasons.
   *
   * @param data the {@link FuzzedDataProvider} instance provided to {@code fuzzerTestOneInput}.
   * @param type the {@link Class} to construct an instance of.
   * @return an instance of {@code type} constructed from the fuzzer input, or {@code null} if
   *     autofuzz failed to create an instance.
   */
  @SuppressWarnings("unchecked")
  public static <T> T consume(FuzzedDataProvider data, Class<T> type) {
    try {
      return (T) CONSUME.invokeExact(data, type);
    } catch (AutofuzzConstructionException ignored) {
      return null;
    } catch (Throwable t) {
      rethrowUnchecked(t);
      // Not reached.
      return null;
    }
  }

  /**
   * Instructs the fuzzer to guide its mutations towards making {@code current} equal to {@code
   * target}.
   *
   * If the relation between the raw fuzzer input and the value of {@code current} is relatively
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
   * If the relation between the raw fuzzer input and the value of {@code current} is relatively
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
   * If the relation between the raw fuzzer input and the value of {@code haystack} is relatively
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
   * Call this function from a fuzz target or a hook to help the fuzzer track partial progress
   * (e.g. by passing the length of a common prefix of two lists that should become equal) or
   * explore different values of state that is not directly related to code coverage (see the
   * MazeFuzzer example).
   *
   * <b>Note:</b> This hint only takes effect if the fuzzer is run with the argument
   * {@code -use_value_profile=1}.
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
    // (65536 bits/ 128 bits per id = 512 ids).

    // We use tracePcIndir as a way to set a bit in libFuzzer's value profile bitmap. In
    // TracePC::HandleCallerCallee, which is what this function ultimately calls through to, the
    // lower 12 bits of each argument are combined into a 24-bit index into the bitmap, which is
    // then reduced modulo a 16-bit prime. To keep the modulo bias small, we should fill as many
    // of the relevant bits as possible. However, there are the following restrictions:
    // 1. Since we use the return address trampoline to set the caller address indirectly, its
    //    upper 3 bits are fixed, which leaves a total of 21 variable bits on x86_64.
    // 2. On arm64 macOS, where every instruction is aligned to 4 bytes, the lower 2 bits of the
    //    caller address will always be zero, further reducing the number of variable bits in the
    //    caller parameter to 7.
    // https://github.com/llvm/llvm-project/blob/c12d49c4e286fa108d4d69f1c6d2b8d691993ffd/compiler-rt/lib/fuzzer/FuzzerTracePC.cpp#L121
    // Even taking these restrictions into consideration, we pass state in the lowest bits of the
    // caller address, which is used to form the lowest bits of the bitmap index. This should result
    // in the best caching behavior as state is expected to change quickly in consecutive runs and
    // in this way all its bitmap entries would be located close to each other in memory.
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
   * <b>Note:</b> This method must only be called from a method hook. In a
   * fuzz target, simply throw an exception to trigger a finding.
   * @param finding the finding that Jazzer should report
   */
  public static void reportFindingFromHook(Throwable finding) {
    try {
      JAZZER_INTERNAL.getMethod("reportFindingFromHook", Throwable.class).invoke(null, finding);
    } catch (NullPointerException | IllegalAccessException | NoSuchMethodException e) {
      // We can only reach this point if the runtime is not in the classpath, but it must be if
      // hooks work and this function should only be called from them.
      System.err.println("ERROR: Jazzer.reportFindingFromHook must be called from a method hook");
      System.exit(1);
    } catch (InvocationTargetException e) {
      // reportFindingFromHook throws a HardToCatchThrowable, which will bubble up wrapped in an
      // InvocationTargetException that should not be stopped here.
      if (e.getCause().getClass().getName().endsWith(".HardToCatchError")) {
        throw(Error) e.getCause();
      } else {
        e.printStackTrace();
      }
    }
  }

  /**
   * Register a callback to be executed right before the fuzz target is executed for the first time.
   *
   * This can be used to disable hooks until after Jazzer has been fully initializing, e.g. to
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
    String rawSeed = System.getProperty("jazzer.seed");
    if (rawSeed == null) {
      return new SecureRandom().nextInt();
    }
    // If jazzer.seed is set, we expect it to be a valid integer.
    return Integer.parseUnsignedInt(rawSeed);
  }

  // Rethrows a (possibly checked) exception while avoiding a throws declaration.
  @SuppressWarnings("unchecked")
  private static <T extends Throwable> void rethrowUnchecked(Throwable t) throws T {
    throw(T) t;
  }
}
