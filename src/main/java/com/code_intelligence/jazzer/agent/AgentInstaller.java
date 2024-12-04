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

package com.code_intelligence.jazzer.agent;

import static com.code_intelligence.jazzer.agent.AgentUtils.extractBootstrapJar;
import static com.code_intelligence.jazzer.runtime.Constants.IS_ANDROID;

import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicBoolean;
import net.bytebuddy.agent.ByteBuddyAgent;

public class AgentInstaller {
  private static final AtomicBoolean hasBeenInstalled = new AtomicBoolean();

  /**
   * Appends the parts of Jazzer that have to be visible to all classes, including those in the Java
   * standard library, to the bootstrap class loader path. Additionally, if enableAgent is true,
   * also enables the Jazzer agent that instruments classes for fuzzing.
   */
  public static void install(boolean enableAgent) {
    // Only install the agent once.
    if (!hasBeenInstalled.compareAndSet(false, true)) {
      return;
    }

    if (IS_ANDROID) {
      return;
    }

    Instrumentation instrumentation = ByteBuddyAgent.install();
    instrumentation.appendToBootstrapClassLoaderSearch(extractBootstrapJar());
    if (!enableAgent) {
      return;
    }
    try {
      Class<?> agent = Class.forName("com.code_intelligence.jazzer.agent.Agent");
      Method install = agent.getMethod("install", Instrumentation.class);
      install.invoke(null, instrumentation);
    } catch (ClassNotFoundException
        | InvocationTargetException
        | NoSuchMethodException
        | IllegalAccessException e) {
      throw new IllegalStateException("Failed to run Agent.install", e);
    }
  }
}
