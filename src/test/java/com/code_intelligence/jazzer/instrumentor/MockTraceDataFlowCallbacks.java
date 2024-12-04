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

package com.code_intelligence.jazzer.instrumentor;

import java.util.ArrayList;
import java.util.List;

@SuppressWarnings("unused")
public class MockTraceDataFlowCallbacks {
  private static List<String> hookCalls;
  private static int assertedCalls;

  public static void init() {
    hookCalls = new ArrayList<>();
    assertedCalls = 0;
  }

  public static boolean hookCall(String expectedCall) {
    if (assertedCalls >= hookCalls.size()) {
      System.err.println(
          "Not seen ("
              + hookCalls.size()
              + " calls, but "
              + (assertedCalls + 1)
              + " expected): "
              + expectedCall);
      return false;
    }

    if (!hookCalls.get(assertedCalls).equals(expectedCall)) {
      System.err.println("Call " + expectedCall + " not seen, got " + hookCalls.get(assertedCalls));
      return false;
    }

    assertedCalls++;
    return true;
  }

  public static boolean finish() {
    if (assertedCalls == hookCalls.size()) return true;
    System.err.println("The following calls were not asserted:");
    for (int i = assertedCalls; i < hookCalls.size(); i++) {
      System.err.println(hookCalls.get(i));
    }

    return false;
  }

  public static void traceCmpLong(long arg1, long arg2, int pc) {
    hookCalls.add("LCMP: " + Math.min(arg1, arg2) + ", " + Math.max(arg1, arg2));
  }

  public static void traceCmpInt(int arg1, int arg2, int pc) {
    hookCalls.add("ICMP: " + Math.min(arg1, arg2) + ", " + Math.max(arg1, arg2));
  }

  public static void traceConstCmpInt(int arg1, int arg2, int pc) {
    hookCalls.add("CICMP: " + arg1 + ", " + arg2);
  }

  public static void traceDivInt(int val, int pc) {
    hookCalls.add("IDIV: " + val);
  }

  public static void traceDivLong(long val, int pc) {
    hookCalls.add("LDIV: " + val);
  }

  public static void traceGep(long idx, int pc) {
    hookCalls.add("GEP: " + idx);
  }

  public static void traceSwitch(long switchValue, long[] libfuzzerCaseValues, int pc) {
    if (libfuzzerCaseValues.length < 3
        // number of case values must match length
        || libfuzzerCaseValues[0] != libfuzzerCaseValues.length - 2
        // bit size of case values is always 32 (int)
        || libfuzzerCaseValues[1] != 32) {
      hookCalls.add("INVALID_SWITCH");
      return;
    }

    StringBuilder builder = new StringBuilder("SWITCH: " + switchValue + ", (");
    for (int i = 2; i < libfuzzerCaseValues.length; i++) {
      builder.append(libfuzzerCaseValues[i]);
      builder.append(", ");
    }
    builder.append(")");
    hookCalls.add(builder.toString());
  }

  public static int traceCmpLongWrapper(long value1, long value2, int pc) {
    traceCmpLong(value1, value2, pc);
    // Long.compare serves as a substitute for the lcmp opcode here
    // (behaviour is the same)
    return Long.compare(value1, value2);
  }
}
