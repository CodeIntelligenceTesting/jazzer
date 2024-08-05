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
