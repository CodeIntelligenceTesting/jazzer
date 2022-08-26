/*
 * Copyright 2022 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.driver;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.utils.ManifestUtils;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;
import java.util.stream.Stream;

class FuzzTargetFinder {
  static class FuzzTarget {
    public final boolean useFuzzedDataProvider;
    public final Method method;
    public final Callable<Object> newInstance;
    public final Optional<Method> tearDown;

    public FuzzTarget(boolean usesFuzzedDataProvider, Method method, Callable<Object> newInstance,
        Optional<Method> tearDown) {
      this.useFuzzedDataProvider = usesFuzzedDataProvider;
      this.method = method;
      this.newInstance = newInstance;
      this.tearDown = tearDown;
    }
  }

  private static final String AUTOFUZZ_FUZZ_TARGET =
      "com.code_intelligence.jazzer.autofuzz.FuzzTarget";
  private static final String FUZZ_TEST_ANNOTATION = "com.code_intelligence.jazzer.junit.FuzzTest";
  private static final String FUZZER_TEST_ONE_INPUT = "fuzzerTestOneInput";
  private static final String FUZZER_INITIALIZE = "fuzzerInitialize";
  private static final String FUZZER_TEAR_DOWN = "fuzzerTearDown";

  static String findFuzzTargetClassName() {
    if (!Opt.autofuzz.isEmpty()) {
      return AUTOFUZZ_FUZZ_TARGET;
    }
    if (!Opt.targetClass.isEmpty()) {
      return Opt.targetClass;
    }
    return ManifestUtils.detectFuzzTargetClass();
  }

  /**
   * @throws IllegalArgumentException if the fuzz target method is invalid or couldn't be found
   * @param clazz the fuzz target class
   * @return a {@link FuzzTarget}
   */
  static FuzzTarget findFuzzTarget(Class<?> clazz) {
    return findFuzzTargetByAnnotation(clazz).orElseGet(() -> findFuzzTargetByMethodName(clazz));
  }

  // Finds and validates methods annotated with @FuzzTest.
  private static Optional<FuzzTarget> findFuzzTargetByAnnotation(Class<?> clazz) {
    // Match by class name rather than identity so that the Jazzer driver package doesn't have to
    // depend on the JUnit package.
    List<Method> annotatedMethods =
        Arrays.stream(clazz.getDeclaredMethods())
            .filter(method
                -> Arrays.stream(method.getAnnotations())
                       .anyMatch(annotation
                           -> annotation.annotationType().getName().equals(FUZZ_TEST_ANNOTATION)))
            .collect(Collectors.toList());
    if (annotatedMethods.isEmpty()) {
      return Optional.empty();
    }

    Method method;
    if (annotatedMethods.size() > 1) {
      if (Opt.targetMethod.isEmpty()) {
        throw new IllegalArgumentException(String.format(
            "%s contains multiple methods annotated with @FuzzTest, but --target_method hasn't been specified",
            clazz.getName()));
      }
      List<Method> targetMethods = annotatedMethods.stream()
                                       .filter(m -> Opt.targetMethod.equals(m.getName()))
                                       .collect(Collectors.toList());
      if (targetMethods.isEmpty()) {
        throw new IllegalArgumentException(
            String.format("%s contains no method called '%s' that is annotated with @FuzzTest",
                clazz.getName(), Opt.targetMethod));
      }
      if (targetMethods.size() > 1) {
        throw new IllegalArgumentException(String.format(
            "%s contains multiple methods called '%s' that are annotated with @FuzzTest - this is currently not supported",
            clazz.getName(), Opt.targetMethod));
      }
      method = targetMethods.get(0);
    } else {
      method = annotatedMethods.get(0);
    }

    // The following checks ensure compatibility with the JUnit concept of a test class and test
    // method.
    // https://junit.org/junit5/docs/5.9.0/user-guide/#writing-tests-definitions
    if (Modifier.isPrivate(method.getModifiers())) {
      throw new IllegalArgumentException(
          String.format("Methods annotated with @FuzzTest must not be private, got %s in %s",
              method.getName(), clazz.getName()));
    }
    if (Modifier.isStatic(method.getModifiers())) {
      throw new IllegalArgumentException(
          String.format("Methods annotated with @FuzzTest must not be static, got %s in %s",
              method.getName(), clazz.getName()));
    }
    if (method.getParameterCount() > 1) {
      throw new IllegalArgumentException(String.format(
          "Methods annotated with @FuzzTest must take a single parameter, got %d for %s in %s",
          method.getParameterCount(), method.getName(), clazz.getName()));
    }

    Class<?> parameter = method.getParameterTypes()[0];
    if (parameter != byte[].class && parameter != FuzzedDataProvider.class) {
      throw new IllegalArgumentException(String.format(
          "Methods annotated with @FuzzTest must take a single byte[] or FuzzedDataProvider parameter, got %s for %s in %s",
          parameter.getName(), method.getName(), clazz.getName()));
    }

    if (clazz.getDeclaredConstructors().length != 1) {
      throw new IllegalArgumentException(String.format(
          "Classes containing a method annotated with @FuzzTest must declare exactly one constructor, got multiple in %s",
          clazz.getName()));
    }
    Constructor<?> constructor = clazz.getDeclaredConstructors()[0];
    // JUnit 5 supports injected constructor parameters, but we don't.
    if (constructor.getParameterCount() > 0) {
      throw new IllegalArgumentException(String.format(
          "The constructor of a class containing a method annotated with @FuzzTest must take no parameters, got a non-zero number in %s",
          clazz.getName()));
    }

    // Both the constructor and the method may not be accessible - JUnit test classes and methods
    // are usually declared without access modifiers and thus package-private.
    method.setAccessible(true);
    constructor.setAccessible(true);

    // TODO: If it should become necessary, implement support for @AfterAll/@AfterEach as
    //  JUnit-idiomatic replacements for fuzzerTearDown.
    return Optional.of(new FuzzTarget(
        parameter == FuzzedDataProvider.class, method, constructor::newInstance, Optional.empty()));
  }

  // Finds the traditional static fuzzerTestOneInput fuzz target method.
  private static FuzzTarget findFuzzTargetByMethodName(Class<?> clazz) {
    Optional<Method> bytesFuzzTarget =
        targetPublicStaticMethod(clazz, FUZZER_TEST_ONE_INPUT, byte[].class);
    Optional<Method> dataFuzzTarget =
        targetPublicStaticMethod(clazz, FUZZER_TEST_ONE_INPUT, FuzzedDataProvider.class);
    if (bytesFuzzTarget.isPresent() == dataFuzzTarget.isPresent()) {
      throw new IllegalArgumentException(String.format(
          "%s must define exactly one of the following two functions:%n"
              + "public static void fuzzerTestOneInput(byte[] ...)%n"
              + "public static void fuzzerTestOneInput(FuzzedDataProvider ...)%n"
              + "Note: Fuzz targets returning boolean are no longer supported; exceptions should be thrown instead of returning true.",
          clazz.getName()));
    }

    Callable<Object> initialize =
        Stream
            .of(targetPublicStaticMethod(clazz, FUZZER_INITIALIZE, String[].class)
                    .map(init -> (Callable<Object>) () -> {
                      init.invoke(null, (Object) Opt.targetArgs.toArray(new String[] {}));
                      return null;
                    }),
                targetPublicStaticMethod(clazz, FUZZER_INITIALIZE)
                    .map(init -> (Callable<Object>) () -> {
                      init.invoke(null);
                      return null;
                    }))
            .filter(Optional::isPresent)
            .map(Optional::get)
            .findFirst()
            .orElse(() -> null);

    return new FuzzTarget(dataFuzzTarget.isPresent(),
        dataFuzzTarget.orElseGet(bytesFuzzTarget::get), initialize,
        targetPublicStaticMethod(clazz, FUZZER_TEAR_DOWN));
  }

  private static Optional<Method> targetPublicStaticMethod(
      Class<?> clazz, String name, Class<?>... parameterTypes) {
    try {
      Method method = clazz.getMethod(name, parameterTypes);
      if (!Modifier.isStatic(method.getModifiers()) || !Modifier.isPublic(method.getModifiers())) {
        return Optional.empty();
      }
      return Optional.of(method);
    } catch (NoSuchMethodException e) {
      return Optional.empty();
    }
  }
}
