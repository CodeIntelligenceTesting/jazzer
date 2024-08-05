/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.driver;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.lang.reflect.Method;

public class FuzzTargetHolder {
  public static FuzzTarget autofuzzFuzzTarget(LifecycleMethodsInvoker lifecycleMethodsInvoker) {
    try {
      Method fuzzerTestOneInput =
          com.code_intelligence.jazzer.autofuzz.FuzzTarget.class.getMethod(
              "fuzzerTestOneInput", FuzzedDataProvider.class);
      return new FuzzTargetHolder.FuzzTarget(fuzzerTestOneInput, lifecycleMethodsInvoker);
    } catch (NoSuchMethodException e) {
      throw new IllegalStateException(e);
    }
  }

  public static final FuzzTarget AUTOFUZZ_FUZZ_TARGET =
      autofuzzFuzzTarget(
          LibFuzzerLifecycleMethodsInvoker.of(
              com.code_intelligence.jazzer.autofuzz.FuzzTarget.class));

  /** The fuzz target that {@link FuzzTargetRunner} should fuzz. */
  public static FuzzTarget fuzzTarget;

  public static class FuzzTarget {
    public final Method method;
    public final LifecycleMethodsInvoker lifecycleMethodsInvoker;

    public FuzzTarget(Method method, LifecycleMethodsInvoker lifecycleMethodsInvoker) {
      this.method = method;
      this.lifecycleMethodsInvoker = lifecycleMethodsInvoker;
    }

    public boolean usesFuzzedDataProvider() {
      return this.method.getParameterCount() == 1
          && this.method.getParameterTypes()[0] == FuzzedDataProvider.class;
    }
  }
}
