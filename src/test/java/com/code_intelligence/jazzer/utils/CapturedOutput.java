/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.utils;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

public final class CapturedOutput {

  public static Output withCapturedOutput(SideEffect sideeffect) {
    ByteArrayOutputStream outs = new ByteArrayOutputStream();
    ByteArrayOutputStream errs = new ByteArrayOutputStream();
    Log.fixOutErr(new PrintStream(outs), new PrintStream(errs));
    sideeffect.call();
    return new Output(outs.toString(), errs.toString());
  }

  public static class Output {
    public final String out;
    public final String err;

    Output(String out, String err) {
      this.out = out;
      this.err = err;
    }
  }

  @FunctionalInterface
  public interface SideEffect {
    void call();
  }

  private CapturedOutput() {}
}
