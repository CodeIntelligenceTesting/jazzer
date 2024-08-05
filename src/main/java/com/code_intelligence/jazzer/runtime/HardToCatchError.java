/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.runtime;

import java.io.PrintStream;
import java.io.PrintWriter;

/** An Error that rethrows itself when any of its getters is invoked. */
public class HardToCatchError extends Error {
  public HardToCatchError() {
    super();
  }

  @Override
  public String getMessage() {
    throw this;
  }

  @Override
  public String getLocalizedMessage() {
    throw this;
  }

  @Override
  public synchronized Throwable initCause(Throwable cause) {
    throw this;
  }

  @Override
  public String toString() {
    throw this;
  }

  @Override
  public void printStackTrace() {
    throw this;
  }

  @Override
  public void printStackTrace(PrintStream s) {
    throw this;
  }

  @Override
  public void printStackTrace(PrintWriter s) {
    throw this;
  }

  @Override
  public StackTraceElement[] getStackTrace() {
    throw this;
  }

  @Override
  public int hashCode() {
    throw this;
  }

  @Override
  public boolean equals(Object obj) {
    throw this;
  }

  @Override
  public Object clone() {
    throw this;
  }
}
