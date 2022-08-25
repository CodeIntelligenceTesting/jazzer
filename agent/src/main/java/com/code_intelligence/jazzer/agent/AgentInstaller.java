// Copyright 2022 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.agent;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.jar.JarFile;
import net.bytebuddy.agent.ByteBuddyAgent;

public class AgentInstaller {
  private static final String BOOTSTRAP_JAR =
      "/com/code_intelligence/jazzer/runtime/jazzer_bootstrap.jar";
  private static final AtomicBoolean hasBeenInstalled = new AtomicBoolean();
  private static File bootstrapJar;

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
    Instrumentation instrumentation = ByteBuddyAgent.install();
    bootstrapJar = extractBootstrapJar();
    try {
      instrumentation.appendToBootstrapClassLoaderSearch(new JarFile(bootstrapJar));
    } catch (IOException e) {
      throw new IllegalStateException(
          "Failed to append Jazzer agent bootstrap jar to bootstrap class loader search", e);
    }
    if (!enableAgent) {
      return;
    }
    try {
      Class<?> agent = Class.forName("com.code_intelligence.jazzer.agent.Agent");
      Method install = agent.getMethod("install", Instrumentation.class);
      install.invoke(null, instrumentation);
    } catch (ClassNotFoundException | InvocationTargetException | NoSuchMethodException
        | IllegalAccessException e) {
      throw new IllegalStateException("Failed to run Agent.install", e);
    }
  }

  public static void deleteTemporaryFiles() {
    if (bootstrapJar != null) {
      bootstrapJar.delete();
    }
  }

  private static File extractBootstrapJar() {
    try (InputStream bootstrapJarStream = AgentInstaller.class.getResourceAsStream(BOOTSTRAP_JAR)) {
      if (bootstrapJarStream == null) {
        throw new IllegalStateException("Failed to find Jazzer agent boostrap jar in resources");
      }
      File bootstrapJar = Files.createTempFile("jazzer-agent-", ".jar").toFile();
      bootstrapJar.deleteOnExit();
      Files.copy(bootstrapJarStream, bootstrapJar.toPath(), StandardCopyOption.REPLACE_EXISTING);
      return bootstrapJar;
    } catch (IOException e) {
      throw new IllegalStateException("Failed to extract Jazzer agent bootstrap jar", e);
    }
  }
}
