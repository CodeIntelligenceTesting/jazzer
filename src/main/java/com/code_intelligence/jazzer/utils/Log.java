/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.utils;

import java.io.PrintStream;

/**
 * Provides static functions that should be used for any kind of output (structured or unstructured)
 * emitted by the fuzzer.
 *
 * <p>Output is printed to {@link System#err} and {@link System#out} until {@link
 * Log#fixOutErr(PrintStream, PrintStream)} is called, which locks in the {@link PrintStream}s to be
 * used from there on.
 */
public class Log {
  // Don't use directly, always use getOut() and getErr() instead - when these fields haven't been
  // set yet, we want to resolve them dynamically as System.out and System.err, which may change
  // over the course of the fuzzer's lifetime.
  private static PrintStream fixedOut;
  private static PrintStream fixedErr;

  /** The {@link PrintStream}s to use for all output from this call on. */
  public static void fixOutErr(PrintStream out, PrintStream err) {
    if (out == null) {
      throw new IllegalArgumentException("out must not be null");
    }
    if (err == null) {
      throw new IllegalArgumentException("err must not be null");
    }
    Log.fixedOut = out;
    Log.fixedErr = err;
  }

  public static void println(String message) {
    getErr().println(message);
  }

  public static void structuredOutput(String output) {
    getOut().println(output);
  }

  public static void info(String message) {
    println("INFO: ", message, null);
  }

  public static void warn(String message) {
    warn(message, null);
  }

  public static void warn(String message, Throwable t) {
    println("WARN: ", message, t);
  }

  public static void error(String message) {
    error(message, null);
  }

  public static void error(Throwable t) {
    error(null, t);
  }

  public static void error(String message, Throwable t) {
    println("ERROR: ", message, t);
  }

  public static void finding(Throwable t) {
    println("\n== Java Exception: ", null, t);
  }

  private static void println(String prefix, String message, Throwable t) {
    PrintStream err = getErr();
    err.print(prefix);
    if (message != null) {
      err.println(message + (t != null ? ":" : ""));
    }
    if (t != null) {
      t.printStackTrace(err);
    }
  }

  private static PrintStream getOut() {
    return fixedOut != null ? fixedOut : System.out;
  }

  private static PrintStream getErr() {
    return fixedErr != null ? fixedErr : System.err;
  }
}
