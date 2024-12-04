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

import java.nio.ByteBuffer;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Stack;
import java.util.Vector;

public class TraceDataFlowInstrumentationTarget implements DynamicTestContract {
  volatile long long1 = 1;
  volatile long long2 = 1;
  volatile long long3 = 2;
  volatile long long4 = 3;

  volatile int int1 = 4;
  volatile int int2 = 4;
  volatile int int3 = 6;
  volatile int int4 = 5;

  volatile int switchValue = 1200;

  @SuppressWarnings("ReturnValueIgnored")
  @Override
  public Map<String, Boolean> selfCheck() {
    Map<String, Boolean> results = new HashMap<>();

    results.put("longCompareEq", long1 == long2);
    results.put("longCompareNe", long3 != long4);

    results.put("intCompareEq", int1 == int2);
    results.put("intCompareNe", int3 != int4);
    results.put("intCompareLt", int4 < int3);
    results.put("intCompareLe", int4 <= int3);
    results.put("intCompareGt", int3 > int4);
    results.put("intCompareGe", int3 >= int4);

    // Not instrumented since all case values are non-negative and < 256.
    switch (switchValue) {
      case 119:
      case 120:
      case 121:
        results.put("tableSwitchUninstrumented", false);
        break;
      default:
        results.put("tableSwitchUninstrumented", true);
    }

    // Not instrumented since all case values are non-negative and < 256.
    switch (switchValue) {
      case 1:
      case 200:
        results.put("lookupSwitchUninstrumented", false);
        break;
      default:
        results.put("lookupSwitchUninstrumented", true);
    }

    results.put("emptySwitchUninstrumented", false);
    switch (switchValue) {
      default:
        results.put("emptySwitchUninstrumented", true);
    }

    switch (switchValue) {
      case 1000:
      case 1001:
        // case 1002: The tableswitch instruction will contain a gap case for 1002.
      case 1003:
        results.put("tableSwitch", false);
        break;
      default:
        results.put("tableSwitch", true);
    }

    switch (-switchValue) {
      case -1200:
        results.put("lookupSwitch", true);
        break;
      case -1:
      case -10:
      case -1000:
      case 200:
      default:
        results.put("lookupSwitch", false);
    }

    results.put("intDiv", (int3 / 2) == 3);

    results.put("longDiv", (long4 / 2) == 1);

    String[] referenceArray = {"foo", "foo", "bar"};
    boolean[] boolArray = {false, false, true};
    byte[] byteArray = {0, 0, 2};
    char[] charArray = {0, 0, 0, 3};
    double[] doubleArray = {0, 0, 0, 0, 4};
    float[] floatArray = {0, 0, 0, 0, 0, 5};
    int[] intArray = {0, 0, 0, 0, 0, 0, 6};
    long[] longArray = {0, 0, 0, 0, 0, 0, 0, 7};
    short[] shortArray = {0, 0, 0, 0, 0, 0, 0, 0, 8};

    results.put("referenceArrayGep", referenceArray[2].equals("bar"));
    results.put("boolArrayGep", boolArray[2]);
    results.put("byteArrayGep", byteArray[2] == 2);
    results.put("charArrayGep", charArray[3] == 3);
    results.put("doubleArrayGep", doubleArray[4] == 4);
    results.put("floatArrayGep", floatArray[5] == 5);
    results.put("intArrayGep", intArray[6] == 6);
    results.put("longArrayGep", longArray[7] == 7);
    results.put("shortArrayGep", shortArray[8] == 8);

    ByteBuffer buffer = ByteBuffer.allocate(100);
    buffer.get(2);
    buffer.getChar(3);
    buffer.getDouble(4);
    buffer.getFloat(5);
    buffer.getInt(6);
    buffer.getLong(7);
    buffer.getShort(8);

    "foobarbazbat".charAt(9);
    "foobarbazbat".codePointAt(10);
    new StringBuilder("foobarbazbat").charAt(11);

    (new Vector<>(Collections.nCopies(20, "foo"))).get(12);
    (new ArrayList<>(Collections.nCopies(20, "foo"))).get(13);
    Stack<String> stack = new Stack<>();
    for (int i = 0; i < 20; i++) stack.push("foo");
    stack.get(14);
    stack.get(15);
    ((AbstractList<String>) stack).get(16);
    ((List<String>) stack).get(17);

    return results;
  }
}
