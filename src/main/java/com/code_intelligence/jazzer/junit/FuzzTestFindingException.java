/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.junit;

/**
 * Wrapper exception that is used to distinguish between handled findings and unhandled execution
 * exceptions.
 */
public class FuzzTestFindingException extends RuntimeException {
  public FuzzTestFindingException(Throwable finding) {
    super(finding);
  }
}
