/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.api;

/**
 * A specialization of {@link AutoCloseable} without a {@code throws} declarations on {@link
 * #close()}.
 */
public interface SilentCloseable extends AutoCloseable {
  @Override
  void close();
}
