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
