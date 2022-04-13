// Copyright 2021 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.code_intelligence.jazzer.runtime;

import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;
import java.util.Arrays;
import java.util.ConcurrentModificationException;
import java.util.Map;
import java.util.TreeMap;

@SuppressWarnings("unused")
final public class TraceCmpHooks {
  @MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.Byte", targetMethod = "compare",
      targetMethodDescriptor = "(BB)I")
  @MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.Byte",
      targetMethod = "compareUnsigned", targetMethodDescriptor = "(BB)I")
  @MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.Short", targetMethod = "compare",
      targetMethodDescriptor = "(SS)I")
  @MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.Short",
      targetMethod = "compareUnsigned", targetMethodDescriptor = "(SS)I")
  @MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.Integer",
      targetMethod = "compare", targetMethodDescriptor = "(II)I")
  @MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.Integer",
      targetMethod = "compareUnsigned", targetMethodDescriptor = "(II)I")
  public static void
  integerCompare(MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    TraceDataFlowNativeCallbacks.traceCmpInt((int) arguments[0], (int) arguments[1], hookId);
  }

  @MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.Byte",
      targetMethod = "compareTo", targetMethodDescriptor = "(Ljava/lang/Byte;)I")
  @MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.Short",
      targetMethod = "compareTo", targetMethodDescriptor = "(Ljava/lang/Short;)I")
  @MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.Integer",
      targetMethod = "compareTo", targetMethodDescriptor = "(Ljava/lang/Integer;)I")
  public static void
  integerCompareTo(MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    TraceDataFlowNativeCallbacks.traceCmpInt((int) thisObject, (int) arguments[0], hookId);
  }

  @MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.Long", targetMethod = "compare",
      targetMethodDescriptor = "(JJ)I")
  @MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.Long",
      targetMethod = "compareUnsigned", targetMethodDescriptor = "(JJ)I")
  public static void
  longCompare(MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    TraceDataFlowNativeCallbacks.traceCmpLong((long) arguments[0], (long) arguments[1], hookId);
  }

  @MethodHook(type = HookType.BEFORE, targetClassName = "java.lang.Long",
      targetMethod = "compareTo", targetMethodDescriptor = "(Ljava/lang/Long;)I")
  public static void
  longCompareTo(MethodHandle method, Long thisObject, Object[] arguments, int hookId) {
    TraceDataFlowNativeCallbacks.traceCmpLong(thisObject, (long) arguments[0], hookId);
  }

  @MethodHook(type = HookType.AFTER, targetClassName = "java.lang.String", targetMethod = "equals")
  @MethodHook(type = HookType.AFTER, targetClassName = "java.lang.String",
      targetMethod = "equalsIgnoreCase")
  public static void
  equals(
      MethodHandle method, String thisObject, Object[] arguments, int hookId, Boolean returnValue) {
    if (arguments[0] instanceof String && !returnValue) {
      // The precise value of the result of the comparison is not used by libFuzzer as long as it is
      // non-zero.
      TraceDataFlowNativeCallbacks.traceStrcmp(thisObject, (String) arguments[0], 1, hookId);
    }
  }

  @MethodHook(type = HookType.AFTER, targetClassName = "java.lang.Object", targetMethod = "equals")
  @MethodHook(
      type = HookType.AFTER, targetClassName = "java.lang.CharSequence", targetMethod = "equals")
  @MethodHook(type = HookType.AFTER, targetClassName = "java.lang.Number", targetMethod = "equals")
  public static void
  genericEquals(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Boolean returnValue) {
    if (!returnValue && arguments[0] != null && thisObject.getClass() == arguments[0].getClass()) {
      TraceDataFlowNativeCallbacks.traceGenericCmp(thisObject, arguments[0], hookId);
    }
  }

  @MethodHook(
      type = HookType.AFTER, targetClassName = "java.lang.String", targetMethod = "compareTo")
  @MethodHook(type = HookType.AFTER, targetClassName = "java.lang.String",
      targetMethod = "compareToIgnoreCase")
  public static void
  compareTo(
      MethodHandle method, String thisObject, Object[] arguments, int hookId, Integer returnValue) {
    if (arguments[0] instanceof String && returnValue != 0) {
      TraceDataFlowNativeCallbacks.traceStrcmp(
          thisObject, (String) arguments[0], returnValue, hookId);
    }
  }

  @MethodHook(
      type = HookType.AFTER, targetClassName = "java.lang.String", targetMethod = "contentEquals")
  public static void
  contentEquals(
      MethodHandle method, String thisObject, Object[] arguments, int hookId, Boolean returnValue) {
    if (arguments[0] instanceof CharSequence && !returnValue) {
      TraceDataFlowNativeCallbacks.traceStrcmp(
          thisObject, ((CharSequence) arguments[0]).toString(), 1, hookId);
    }
  }

  @MethodHook(type = HookType.AFTER, targetClassName = "java.lang.String",
      targetMethod = "regionMatches", targetMethodDescriptor = "(ZILjava/lang/String;II)Z")
  public static void
  regionsMatches5(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Boolean returnValue) {
    if (!returnValue) {
      int toffset = (int) arguments[1];
      String other = (String) arguments[2];
      int ooffset = (int) arguments[3];
      int len = (int) arguments[4];
      regionMatchesInternal((String) thisObject, toffset, other, ooffset, len, hookId);
    }
  }

  @MethodHook(type = HookType.AFTER, targetClassName = "java.lang.String",
      targetMethod = "regionMatches", targetMethodDescriptor = "(ILjava/lang/String;II)Z")
  public static void
  regionMatches4(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Boolean returnValue) {
    if (!returnValue) {
      int toffset = (int) arguments[0];
      String other = (String) arguments[1];
      int ooffset = (int) arguments[2];
      int len = (int) arguments[3];
      regionMatchesInternal((String) thisObject, toffset, other, ooffset, len, hookId);
    }
  }

  private static void regionMatchesInternal(
      String thisString, int toffset, String other, int ooffset, int len, int hookId) {
    if (toffset < 0 || ooffset < 0)
      return;
    int cappedThisStringEnd = Math.min(toffset + len, thisString.length());
    int cappedOtherStringEnd = Math.min(ooffset + len, other.length());
    String thisPart = thisString.substring(toffset, cappedThisStringEnd);
    String otherPart = other.substring(ooffset, cappedOtherStringEnd);
    TraceDataFlowNativeCallbacks.traceStrcmp(thisPart, otherPart, 1, hookId);
  }

  @MethodHook(
      type = HookType.AFTER, targetClassName = "java.lang.String", targetMethod = "contains")
  public static void
  contains(
      MethodHandle method, String thisObject, Object[] arguments, int hookId, Boolean returnValue) {
    if (arguments[0] instanceof CharSequence && !returnValue) {
      TraceDataFlowNativeCallbacks.traceStrstr(
          thisObject, ((CharSequence) arguments[0]).toString(), hookId);
    }
  }

  @MethodHook(type = HookType.AFTER, targetClassName = "java.lang.String", targetMethod = "indexOf")
  @MethodHook(
      type = HookType.AFTER, targetClassName = "java.lang.String", targetMethod = "lastIndexOf")
  @MethodHook(
      type = HookType.AFTER, targetClassName = "java.lang.StringBuffer", targetMethod = "indexOf")
  @MethodHook(type = HookType.AFTER, targetClassName = "java.lang.StringBuffer",
      targetMethod = "lastIndexOf")
  @MethodHook(
      type = HookType.AFTER, targetClassName = "java.lang.StringBuilder", targetMethod = "indexOf")
  @MethodHook(type = HookType.AFTER, targetClassName = "java.lang.StringBuilder",
      targetMethod = "lastIndexOf")
  public static void
  indexOf(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Integer returnValue) {
    if (arguments[0] instanceof String && returnValue == -1) {
      TraceDataFlowNativeCallbacks.traceStrstr(
          thisObject.toString(), (String) arguments[0], hookId);
    }
  }

  @MethodHook(
      type = HookType.AFTER, targetClassName = "java.lang.String", targetMethod = "startsWith")
  @MethodHook(
      type = HookType.AFTER, targetClassName = "java.lang.String", targetMethod = "endsWith")
  public static void
  startsWith(
      MethodHandle method, String thisObject, Object[] arguments, int hookId, Boolean returnValue) {
    if (!returnValue) {
      TraceDataFlowNativeCallbacks.traceStrstr(thisObject, (String) arguments[0], hookId);
    }
  }

  @MethodHook(type = HookType.AFTER, targetClassName = "java.lang.String", targetMethod = "replace",
      targetMethodDescriptor =
          "(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;")
  public static void
  replace(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, String returnValue) {
    String original = (String) thisObject;
    // Report only if the replacement was not successful.
    if (original.equals(returnValue)) {
      String target = arguments[0].toString();
      TraceDataFlowNativeCallbacks.traceStrstr(original, target, hookId);
    }
  }

  @MethodHook(type = HookType.AFTER, targetClassName = "java.util.Arrays", targetMethod = "equals",
      targetMethodDescriptor = "([B[B)Z")
  public static void
  arraysEquals(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Boolean returnValue) {
    if (returnValue)
      return;
    byte[] first = (byte[]) arguments[0];
    byte[] second = (byte[]) arguments[1];
    TraceDataFlowNativeCallbacks.traceMemcmp(first, second, 1, hookId);
  }

  @MethodHook(type = HookType.AFTER, targetClassName = "java.util.Arrays", targetMethod = "equals",
      targetMethodDescriptor = "([BII[BII)Z")
  public static void
  arraysEqualsRange(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Boolean returnValue) {
    if (returnValue)
      return;
    byte[] first =
        Arrays.copyOfRange((byte[]) arguments[0], (int) arguments[1], (int) arguments[2]);
    byte[] second =
        Arrays.copyOfRange((byte[]) arguments[3], (int) arguments[4], (int) arguments[5]);
    TraceDataFlowNativeCallbacks.traceMemcmp(first, second, 1, hookId);
  }

  @MethodHook(type = HookType.AFTER, targetClassName = "java.util.Arrays", targetMethod = "compare",
      targetMethodDescriptor = "([B[B)I")
  @MethodHook(type = HookType.AFTER, targetClassName = "java.util.Arrays",
      targetMethod = "compareUnsigned", targetMethodDescriptor = "([B[B)I")
  public static void
  arraysCompare(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Integer returnValue) {
    if (returnValue == 0)
      return;
    byte[] first = (byte[]) arguments[0];
    byte[] second = (byte[]) arguments[1];
    TraceDataFlowNativeCallbacks.traceMemcmp(first, second, returnValue, hookId);
  }

  @MethodHook(type = HookType.AFTER, targetClassName = "java.util.Arrays", targetMethod = "compare",
      targetMethodDescriptor = "([BII[BII)I")
  @MethodHook(type = HookType.AFTER, targetClassName = "java.util.Arrays",
      targetMethod = "compareUnsigned", targetMethodDescriptor = "([BII[BII)I")
  public static void
  arraysCompareRange(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Integer returnValue) {
    if (returnValue == 0)
      return;
    byte[] first =
        Arrays.copyOfRange((byte[]) arguments[0], (int) arguments[1], (int) arguments[2]);
    byte[] second =
        Arrays.copyOfRange((byte[]) arguments[3], (int) arguments[4], (int) arguments[5]);
    TraceDataFlowNativeCallbacks.traceMemcmp(first, second, returnValue, hookId);
  }

  // The maximal number of elements of a non-TreeMap Map that will be sorted and searched for the
  // key closest to the current lookup key in the mapGet hook.
  private static final int MAX_NUM_KEYS_TO_ENUMERATE = 100;

  @SuppressWarnings({"rawtypes", "unchecked"})
  @MethodHook(type = HookType.AFTER, targetClassName = "java.util.Map", targetMethod = "get")
  public static void mapGet(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Object returnValue) {
    if (returnValue != null)
      return;
    if (thisObject == null)
      return;
    final Map map = (Map) thisObject;
    if (map.size() == 0)
      return;
    final Object currentKey = arguments[0];
    if (currentKey == null)
      return;
    // Find two valid map keys that bracket currentKey.
    // This is a generalization of libFuzzer's __sanitizer_cov_trace_switch:
    // https://github.com/llvm/llvm-project/blob/318942de229beb3b2587df09e776a50327b5cef0/compiler-rt/lib/fuzzer/FuzzerTracePC.cpp#L564
    Object lowerBoundKey = null;
    Object upperBoundKey = null;
    try {
      if (map instanceof TreeMap) {
        final TreeMap treeMap = (TreeMap) map;
        try {
          lowerBoundKey = treeMap.floorKey(currentKey);
          upperBoundKey = treeMap.ceilingKey(currentKey);
        } catch (ClassCastException ignored) {
          // Can be thrown by floorKey and ceilingKey if currentKey is of a type that can't be
          // compared to the maps keys.
        }
      } else if (currentKey instanceof Comparable) {
        final Comparable comparableCurrentKey = (Comparable) currentKey;
        // Find two keys that bracket currentKey.
        // Note: This is not deterministic if map.size() > MAX_NUM_KEYS_TO_ENUMERATE.
        int enumeratedKeys = 0;
        for (Object validKey : map.keySet()) {
          if (!(validKey instanceof Comparable))
            continue;
          final Comparable comparableValidKey = (Comparable) validKey;
          // If the key sorts lower than the non-existing key, but higher than the current lower
          // bound, update the lower bound and vice versa for the upper bound.
          try {
            if (comparableValidKey.compareTo(comparableCurrentKey) < 0
                && (lowerBoundKey == null || comparableValidKey.compareTo(lowerBoundKey) > 0)) {
              lowerBoundKey = validKey;
            }
            if (comparableValidKey.compareTo(comparableCurrentKey) > 0
                && (upperBoundKey == null || comparableValidKey.compareTo(upperBoundKey) < 0)) {
              upperBoundKey = validKey;
            }
          } catch (ClassCastException ignored) {
            // Can be thrown by floorKey and ceilingKey if currentKey is of a type that can't be
            // compared to the maps keys.
          }
          if (enumeratedKeys++ > MAX_NUM_KEYS_TO_ENUMERATE)
            break;
        }
      }
    } catch (ConcurrentModificationException ignored) {
      // map was modified by another thread, skip this invocation
      return;
    }
    // Modify the hook ID so that compares against distinct valid keys are traced separately.
    if (lowerBoundKey != null) {
      TraceDataFlowNativeCallbacks.traceGenericCmp(
          currentKey, lowerBoundKey, hookId + lowerBoundKey.hashCode());
    }
    if (upperBoundKey != null) {
      TraceDataFlowNativeCallbacks.traceGenericCmp(
          currentKey, upperBoundKey, hookId + upperBoundKey.hashCode());
    }
  }
}
