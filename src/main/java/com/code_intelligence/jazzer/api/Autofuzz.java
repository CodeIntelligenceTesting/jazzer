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

/** Static helper functions that allow Jazzer fuzz targets to use Autofuzz. */
public final class Autofuzz {
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
      Class<?> metaClass = Class.forName("com.code_intelligence.jazzer.autofuzz.Meta");
      MethodType consumeType =
          MethodType.methodType(Object.class, FuzzedDataProvider.class, Class.class);
      consume = MethodHandles.publicLookup().findStatic(metaClass, "consume", consumeType);

      autofuzzFunction1 =
          MethodHandles.publicLookup()
              .findStatic(
                  metaClass,
                  "autofuzz",
                  MethodType.methodType(Object.class, FuzzedDataProvider.class, Function1.class));
      autofuzzFunction2 =
          MethodHandles.publicLookup()
              .findStatic(
                  metaClass,
                  "autofuzz",
                  MethodType.methodType(Object.class, FuzzedDataProvider.class, Function2.class));
      autofuzzFunction3 =
          MethodHandles.publicLookup()
              .findStatic(
                  metaClass,
                  "autofuzz",
                  MethodType.methodType(Object.class, FuzzedDataProvider.class, Function3.class));
      autofuzzFunction4 =
          MethodHandles.publicLookup()
              .findStatic(
                  metaClass,
                  "autofuzz",
                  MethodType.methodType(Object.class, FuzzedDataProvider.class, Function4.class));
      autofuzzFunction5 =
          MethodHandles.publicLookup()
              .findStatic(
                  metaClass,
                  "autofuzz",
                  MethodType.methodType(Object.class, FuzzedDataProvider.class, Function5.class));
      autofuzzConsumer1 =
          MethodHandles.publicLookup()
              .findStatic(
                  metaClass,
                  "autofuzz",
                  MethodType.methodType(void.class, FuzzedDataProvider.class, Consumer1.class));
      autofuzzConsumer2 =
          MethodHandles.publicLookup()
              .findStatic(
                  metaClass,
                  "autofuzz",
                  MethodType.methodType(void.class, FuzzedDataProvider.class, Consumer2.class));
      autofuzzConsumer3 =
          MethodHandles.publicLookup()
              .findStatic(
                  metaClass,
                  "autofuzz",
                  MethodType.methodType(void.class, FuzzedDataProvider.class, Consumer3.class));
      autofuzzConsumer4 =
          MethodHandles.publicLookup()
              .findStatic(
                  metaClass,
                  "autofuzz",
                  MethodType.methodType(void.class, FuzzedDataProvider.class, Consumer4.class));
      autofuzzConsumer5 =
          MethodHandles.publicLookup()
              .findStatic(
                  metaClass,
                  "autofuzz",
                  MethodType.methodType(void.class, FuzzedDataProvider.class, Consumer5.class));
    } catch (ClassNotFoundException ignore) {
      // Not running in the context of the agent. This is fine as long as no methods are called on
      // this class.
    } catch (NoSuchMethodException | IllegalAccessException e) {
      // This should never happen as the Jazzer API is loaded from the agent and thus should always
      // match the version of the runtime classes.
      // Does not use the Log class as it is unlikely it can be loaded if the Autofuzz classes
      // couldn't be loaded.
      System.err.println("ERROR: Incompatible version of the Jazzer API detected, please update.");
      e.printStackTrace();
      System.exit(1);
    }
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

  private Autofuzz() {}

  /**
   * Attempts to invoke {@code func} with arguments created automatically from the fuzzer input
   * using only public methods available on the classpath.
   *
   * <p><b>Note:</b> This function is inherently heuristic and may fail to execute {@code func} in
   * meaningful ways for a number of reasons.
   *
   * <p>May throw (unchecked) any {@link Throwable} thrown by {@code func} or an {@link
   * AutofuzzConstructionException} if autofuzz failed to construct the arguments for the call.
   *
   * @param data the {@link FuzzedDataProvider} instance provided to {@code fuzzerTestOneInput}.
   * @param func a method reference for the function to autofuzz. If there are multiple overloads,
   *     resolve ambiguities by explicitly casting to {@link Function1} with (partially) specified
   *     type variables, e.g. {@code (Function1<String, ?>) String::new}.
   * @return the return value of {@code func}, or {@code null} if {@code autofuzz} failed to invoke
   *     the function.
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
   * <p><b>Note:</b> This function is inherently heuristic and may fail to execute {@code func} in
   * meaningful ways for a number of reasons.
   *
   * <p>May throw (unchecked) any {@link Throwable} thrown by {@code func} or an {@link
   * AutofuzzConstructionException} if autofuzz failed to construct the arguments for the call.
   *
   * @param data the {@link FuzzedDataProvider} instance provided to {@code fuzzerTestOneInput}.
   * @param func a method reference for the function to autofuzz. If there are multiple overloads,
   *     resolve ambiguities by explicitly casting to {@link Function2} with (partially) specified
   *     type variables.
   * @return the return value of {@code func}, or {@code null} if {@code autofuzz} failed to invoke
   *     the function.
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
   * <p><b>Note:</b> This function is inherently heuristic and may fail to execute {@code func} in
   * meaningful ways for a number of reasons.
   *
   * <p>May throw (unchecked) any {@link Throwable} thrown by {@code func} or an {@link
   * AutofuzzConstructionException} if autofuzz failed to construct the arguments for the call.
   *
   * @param data the {@link FuzzedDataProvider} instance provided to {@code fuzzerTestOneInput}.
   * @param func a method reference for the function to autofuzz. If there are multiple overloads,
   *     resolve ambiguities by explicitly casting to {@link Function3} with (partially) specified
   *     type variables.
   * @return the return value of {@code func}, or {@code null} if {@code autofuzz} failed to invoke
   *     the function.
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
   * <p><b>Note:</b> This function is inherently heuristic and may fail to execute {@code func} in
   * meaningful ways for a number of reasons.
   *
   * <p>May throw (unchecked) any {@link Throwable} thrown by {@code func} or an {@link
   * AutofuzzConstructionException} if autofuzz failed to construct the arguments for the call.
   *
   * @param data the {@link FuzzedDataProvider} instance provided to {@code fuzzerTestOneInput}.
   * @param func a method reference for the function to autofuzz. If there are multiple overloads,
   *     resolve ambiguities by explicitly casting to {@link Function4} with (partially) specified
   *     type variables.
   * @return the return value of {@code func}, or {@code null} if {@code autofuzz} failed to invoke
   *     the function.
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
   * <p><b>Note:</b> This function is inherently heuristic and may fail to execute {@code func} in
   * meaningful ways for a number of reasons.
   *
   * <p>May throw (unchecked) any {@link Throwable} thrown by {@code func} or an {@link
   * AutofuzzConstructionException} if autofuzz failed to construct the arguments for the call.
   *
   * @param data the {@link FuzzedDataProvider} instance provided to {@code fuzzerTestOneInput}.
   * @param func a method reference for the function to autofuzz. If there are multiple overloads,
   *     resolve ambiguities by explicitly casting to {@link Function5} with (partially) specified
   *     type variables.
   * @return the return value of {@code func}, or {@code null} if {@code autofuzz} failed to invoke
   *     the function.
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
   * <p><b>Note:</b> This function is inherently heuristic and may fail to execute {@code func} in
   * meaningful ways for a number of reasons.
   *
   * <p>May throw (unchecked) any {@link Throwable} thrown by {@code func} or an {@link
   * AutofuzzConstructionException} if autofuzz failed to construct the arguments for the call.
   *
   * @param data the {@link FuzzedDataProvider} instance provided to {@code fuzzerTestOneInput}.
   * @param func a method reference for the function to autofuzz. If there are multiple overloads,
   *     resolve ambiguities by explicitly casting to {@link Consumer1} with explicitly specified
   *     type variable.
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
   * <p><b>Note:</b> This function is inherently heuristic and may fail to execute {@code func} in
   * meaningful ways for a number of reasons.
   *
   * <p>May throw (unchecked) any {@link Throwable} thrown by {@code func} or an {@link
   * AutofuzzConstructionException} if autofuzz failed to construct the arguments for the call.
   *
   * @param data the {@link FuzzedDataProvider} instance provided to {@code fuzzerTestOneInput}.
   * @param func a method reference for the function to autofuzz. If there are multiple overloads,
   *     resolve ambiguities by explicitly casting to {@link Consumer2} with (partially) specified
   *     type variables.
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
   * <p><b>Note:</b> This function is inherently heuristic and may fail to execute {@code func} in
   * meaningful ways for a number of reasons.
   *
   * <p>May throw (unchecked) any {@link Throwable} thrown by {@code func} or an {@link
   * AutofuzzConstructionException} if autofuzz failed to construct the arguments for the call.
   *
   * @param data the {@link FuzzedDataProvider} instance provided to {@code fuzzerTestOneInput}.
   * @param func a method reference for the function to autofuzz. If there are multiple overloads,
   *     resolve ambiguities by explicitly casting to {@link Consumer3} with (partially) specified
   *     type variables.
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
   * <p><b>Note:</b> This function is inherently heuristic and may fail to execute {@code func} in
   * meaningful ways for a number of reasons.
   *
   * <p>May throw (unchecked) any {@link Throwable} thrown by {@code func} or an {@link
   * AutofuzzConstructionException} if autofuzz failed to construct the arguments for the call.
   *
   * @param data the {@link FuzzedDataProvider} instance provided to {@code fuzzerTestOneInput}.
   * @param func a method reference for the function to autofuzz. If there are multiple overloads,
   *     resolve ambiguities by explicitly casting to {@link Consumer4} with (partially) specified
   *     type variables.
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
   * <p><b>Note:</b> This function is inherently heuristic and may fail to execute {@code func} in
   * meaningful ways for a number of reasons.
   *
   * <p>May throw (unchecked) any {@link Throwable} thrown by {@code func} or an {@link
   * AutofuzzConstructionException} if autofuzz failed to construct the arguments for the call.
   *
   * @param data the {@link FuzzedDataProvider} instance provided to {@code fuzzerTestOneInput}.
   * @param func a method reference for the function to autofuzz. If there are multiple overloads,
   *     resolve ambiguities by explicitly casting to {@link Consumer5} with (partially) specified
   *     type variables.
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
   * <p><b>Note:</b> This function is inherently heuristic and may fail to return meaningful values
   * for a variety of reasons.
   *
   * <p>May throw (unchecked) any {@link Throwable} thrown by {@code func} or an {@link
   * AutofuzzConstructionException} if autofuzz failed to construct the arguments for the call.
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

  // Rethrows a (possibly checked) exception while avoiding a throws declaration.
  @SuppressWarnings("unchecked")
  private static <T extends Throwable> void rethrowUnchecked(Throwable t) throws T {
    throw (T) t;
  }
}
