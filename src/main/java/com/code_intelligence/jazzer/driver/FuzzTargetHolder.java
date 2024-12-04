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

    public boolean usesPrimitiveByteArray() {
      return this.method.getParameterCount() == 1
          && this.method.getParameterTypes()[0] == byte[].class;
    }

    public boolean usesFuzzedDataProvider() {
      return this.method.getParameterCount() == 1
          && this.method.getParameterTypes()[0] == FuzzedDataProvider.class;
    }
  }
}
