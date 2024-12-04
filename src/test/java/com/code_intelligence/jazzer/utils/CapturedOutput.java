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
