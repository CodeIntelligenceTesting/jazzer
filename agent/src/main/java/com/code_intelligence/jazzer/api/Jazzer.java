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

import java.lang.reflect.InvocationTargetException;

/**
 * Helper class with static methods that interact with Jazzer at runtime.
 */
final public class Jazzer {
  private static Class jazzerInternal = null;

  static {
    try {
      jazzerInternal = Class.forName("com.code_intelligence.jazzer.runtime.JazzerInternal");
    } catch (ClassNotFoundException ignore) {
      // Not running in the context of the agent. This is fine as long as no methods are called on
      // this class.
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
}
