/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 *
 * This file also contains code licensed under Apache2 license.
 */

package com.code_intelligence.jazzer.driver;

import static com.code_intelligence.jazzer.driver.ReflectionUtils.targetPublicStaticMethod;
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
import java.util.stream.Collectors;

class FuzzTargetFinder {
  private static final String FUZZER_TEST_ONE_INPUT = "fuzzerTestOneInput";

  static String findFuzzTargetClassName() {
    if (!Opt.targetClass.get().isEmpty()) {
      return Opt.targetClass.get();
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
      Log.error(
          String.format(
              "'%s' not found on classpath:%n%n%s%n%nAll required classes must be on the classpath"
                  + " specified via --cp.",
              targetClassName, System.getProperty("java.class.path")));
      exit(1);
      throw new IllegalStateException("Not reached");
    }

    return findFuzzTargetByMethodName(fuzzTargetClass);
  }

  // Finds the traditional static fuzzerTestOneInput fuzz target method.
  private static FuzzTarget findFuzzTargetByMethodName(Class<?> clazz) {
    Method fuzzTargetMethod;
    if (Opt.experimentalMutator.get()) {
      List<Method> fuzzTargetMethods =
          Arrays.stream(clazz.getMethods())
              .filter(method -> "fuzzerTestOneInput".equals(method.getName()))
              .filter(method -> Modifier.isStatic(method.getModifiers()))
              .collect(Collectors.toList());
      if (fuzzTargetMethods.size() != 1) {
        throw new IllegalArgumentException(
            String.format(
                "%s must define exactly one function of this form:%n"
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
        throw new IllegalArgumentException(
            String.format(
                "%s must define exactly one of the following two functions:%npublic static void"
                    + " fuzzerTestOneInput(byte[] ...)%npublic static void"
                    + " fuzzerTestOneInput(FuzzedDataProvider ...)%nNote: Fuzz targets returning"
                    + " boolean are no longer supported; exceptions should be thrown instead of"
                    + " returning true.%nNote: When using the @FuzzTest annotation, you will need"
                    + " to set up JUnit 5, which can be as simple as adding a dependency on"
                    + " org.junit.jupiter:junit-jupiter-engine.",
                clazz.getName()));
      }
      fuzzTargetMethod = dataFuzzTarget.orElseGet(bytesFuzzTarget::get);
    }

    return new FuzzTarget(fuzzTargetMethod, LibFuzzerLifecycleMethodsInvoker.of(clazz));
  }
}
