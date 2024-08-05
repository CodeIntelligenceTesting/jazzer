/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.driver;

import static com.code_intelligence.jazzer.driver.ReflectionUtils.targetPublicStaticMethod;

import com.code_intelligence.jazzer.utils.Log;
import java.lang.reflect.InvocationTargetException;
import java.util.Optional;
import java.util.stream.Stream;

final class LibFuzzerLifecycleMethodsInvoker implements LifecycleMethodsInvoker {
  private static final String FUZZER_INITIALIZE = "fuzzerInitialize";
  private static final String FUZZER_TEAR_DOWN = "fuzzerTearDown";

  private final Optional<ThrowingRunnable> fuzzerInitialize;
  private final Optional<ThrowingRunnable> fuzzerTearDown;

  private LibFuzzerLifecycleMethodsInvoker(
      Optional<ThrowingRunnable> fuzzerInitialize, Optional<ThrowingRunnable> fuzzerTearDown) {
    this.fuzzerInitialize = fuzzerInitialize;
    this.fuzzerTearDown = fuzzerTearDown;
  }

  static LifecycleMethodsInvoker of(Class<?> clazz) {
    Optional<ThrowingRunnable> fuzzerInitialize =
        Stream.of(
                targetPublicStaticMethod(clazz, FUZZER_INITIALIZE, String[].class)
                    .map(
                        init ->
                            (ThrowingRunnable)
                                () ->
                                    init.invoke(
                                        null,
                                        (Object) Opt.targetArgs.get().toArray(new String[] {}))),
                targetPublicStaticMethod(clazz, FUZZER_INITIALIZE)
                    .map(init -> (ThrowingRunnable) () -> init.invoke(null)))
            .filter(Optional::isPresent)
            .map(Optional::get)
            .findFirst();
    Optional<ThrowingRunnable> fuzzerTearDown =
        targetPublicStaticMethod(clazz, FUZZER_TEAR_DOWN)
            .map(tearDown -> () -> tearDown.invoke(null));

    return new LibFuzzerLifecycleMethodsInvoker(fuzzerInitialize, fuzzerTearDown);
  }

  @Override
  public void beforeFirstExecution() throws Throwable {
    if (fuzzerInitialize.isPresent()) {
      try {
        fuzzerInitialize.get().run();
      } catch (InvocationTargetException e) {
        throw e.getCause();
      }
    }
  }

  @Override
  public void beforeEachExecution() {}

  @Override
  public void afterEachExecution() {}

  @Override
  public void afterLastExecution() throws Throwable {
    if (fuzzerTearDown.isPresent()) {
      // Only preserved for backwards compatibility.
      Log.info("calling fuzzerTearDown function");
      try {
        fuzzerTearDown.get().run();
      } catch (InvocationTargetException e) {
        throw e.getCause();
      }
    }
  }

  @Override
  public Object getTestClassInstance() {
    return null;
  }
}
