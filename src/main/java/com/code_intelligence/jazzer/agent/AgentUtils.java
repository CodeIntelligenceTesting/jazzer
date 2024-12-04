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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.jar.JarFile;

final class AgentUtils {
  private static final String BOOTSTRAP_JAR =
      "/com/code_intelligence/jazzer/runtime/jazzer_bootstrap.jar";

  public static JarFile extractBootstrapJar() {
    try (InputStream bootstrapJarStream = AgentUtils.class.getResourceAsStream(BOOTSTRAP_JAR)) {
      if (bootstrapJarStream == null) {
        throw new IllegalStateException("Failed to find Jazzer agent bootstrap jar in resources");
      }
      File bootstrapJar = Files.createTempFile("jazzer-agent-", ".jar").toFile();
      bootstrapJar.deleteOnExit();
      Files.copy(bootstrapJarStream, bootstrapJar.toPath(), StandardCopyOption.REPLACE_EXISTING);
      return new JarFile(bootstrapJar);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to extract Jazzer agent bootstrap jar", e);
    }
  }

  private AgentUtils() {}
}
