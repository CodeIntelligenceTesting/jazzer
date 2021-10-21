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

/**
 * Helper class with static methods that interact with Jazzer at runtime.
 */
final public class Jazzer {
  private static Class<?> jazzerInternal = null;

  private static MethodHandle traceStrcmp = null;
  private static MethodHandle traceStrstr = null;
  private static MethodHandle traceMemcmp = null;

  private static MethodHandle consume = null;
  private static MethodHandle autofuzzFunction1 = null;
  private static MethodHandle autofuzzFunction2 = null;
  private static MethodHandle autofuzzFunction3 = null;
  private static MethodHandle autofuzzFunction4 = null;
  private static MethodHandle autofuzzFunction5 = null;
  private static MethodHandle autofuzzConsumer1 = null;
  private static MethodHandle autofuzzConsumer2 = null;
  private static MethodHandle autofuzzConsumer3 = null;
  private static MethodHandle autofuzzConsumer4 = null;
  private static MethodHandle autofuzzConsumer5 = null;

  static {
    try {
      jazzerInternal = Class.forName("com.code_intelligence.jazzer.runtime.JazzerInternal");
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
      return (R) autofuzzFunction1.invoke(data, func);
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
      return (R) autofuzzFunction2.invoke(data, func);
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
      return (R) autofuzzFunction3.invoke(data, func);
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
      return (R) autofuzzFunction4.invoke(data, func);
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
      return (R) autofuzzFunction5.invoke(data, func);
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
      autofuzzConsumer1.invoke(data, func);
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
      autofuzzConsumer2.invoke(data, func);
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
      autofuzzConsumer3.invoke(data, func);
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
      autofuzzConsumer4.invoke(data, func);
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
      autofuzzConsumer5.invoke(data, func);
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
      return (T) consume.invokeExact(data, type);
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
    try {
      traceStrcmp.invokeExact(current, target, 1, id);
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
    try {
      traceMemcmp.invokeExact(current, target, 1, id);
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
    try {
      traceStrstr.invokeExact(haystack, needle, id);
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
      jazzerInternal.getMethod("reportFindingFromHook", Throwable.class).invoke(null, finding);
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

  // Rethrows a (possibly checked) exception while avoiding a throws declaration.
  @SuppressWarnings("unchecked")
  private static <T extends Throwable> void rethrowUnchecked(Throwable t) throws T {
    throw(T) t;
  }
}
