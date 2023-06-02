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

import static com.code_intelligence.jazzer.runtime.Constants.IS_ANDROID;
import static java.lang.System.exit;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.driver.FuzzTargetHolder.FuzzTarget;
import com.code_intelligence.jazzer.utils.Log;
import com.code_intelligence.jazzer.utils.ManifestUtils;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;
import java.util.stream.Stream;

class FuzzTargetFinder {
  private static final String FUZZER_TEST_ONE_INPUT = "fuzzerTestOneInput";
  private static final String FUZZER_INITIALIZE = "fuzzerInitialize";
  private static final String FUZZER_TEAR_DOWN = "fuzzerTearDown";

  static String findFuzzTargetClassName() {
    if (!Opt.targetClass.isEmpty()) {
      return Opt.targetClass;
    }
    if (IS_ANDROID) {
      // Fuzz target detection tools aren't supported on android
      return null;
    }
    return ManifestUtils.detectFuzzTargetClass();
  }

  /**
   * @throws IllegalArgumentException if the fuzz target method is invalid or couldn't be found
   * @param targetClassName name of the fuzz target class
   * @return a {@link FuzzTarget}
   */
  static FuzzTarget findFuzzTarget(String targetClassName) {
    Class<?> fuzzTargetClass;
    try {
      fuzzTargetClass =
          Class.forName(targetClassName, false, FuzzTargetFinder.class.getClassLoader());
    } catch (ClassNotFoundException e) {
      Log.error(String.format(
          "'%s' not found on classpath:%n%n%s%n%nAll required classes must be on the classpath specified via --cp.",
          targetClassName, System.getProperty("java.class.path")));
      exit(1);
      throw new IllegalStateException("Not reached");
    }

    return findFuzzTargetByMethodName(fuzzTargetClass);
  }

  // Finds the traditional static fuzzerTestOneInput fuzz target method.
  private static FuzzTarget findFuzzTargetByMethodName(Class<?> clazz) {
    Method fuzzTargetMethod;
    if (Opt.experimentalMutator) {
      List<Method> fuzzTargetMethods =
          Arrays.stream(clazz.getMethods())
              .filter(method -> "fuzzerTestOneInput".equals(method.getName()))
              .filter(method -> Modifier.isStatic(method.getModifiers()))
              .collect(Collectors.toList());
      if (fuzzTargetMethods.size() != 1) {
        throw new IllegalArgumentException(
            String.format("%s must define exactly one function of this form:%n"
                    + "public static void fuzzerTestOneInput(...)%n",
                clazz.getName()));
      }
      fuzzTargetMethod = fuzzTargetMethods.get(0);
    } else {
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
      fuzzTargetMethod = dataFuzzTarget.orElseGet(bytesFuzzTarget::get);
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

    return new FuzzTarget(
        fuzzTargetMethod, initialize, targetPublicStaticMethod(clazz, FUZZER_TEAR_DOWN));
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
