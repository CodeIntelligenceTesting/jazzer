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
