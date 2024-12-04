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

import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;
import java.util.*;

@SuppressWarnings("unused")
public final class TraceCmpHooks {
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.lang.Byte",
      targetMethod = "compare",
      targetMethodDescriptor = "(BB)I")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.lang.Byte",
      targetMethod = "compareUnsigned",
      targetMethodDescriptor = "(BB)I")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.lang.Short",
      targetMethod = "compare",
      targetMethodDescriptor = "(SS)I")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.lang.Short",
      targetMethod = "compareUnsigned",
      targetMethodDescriptor = "(SS)I")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.lang.Integer",
      targetMethod = "compare",
      targetMethodDescriptor = "(II)I")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.lang.Integer",
      targetMethod = "compareUnsigned",
      targetMethodDescriptor = "(II)I")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "kotlin.jvm.internal.Intrinsics ",
      targetMethod = "compare",
      targetMethodDescriptor = "(II)I")
  public static void integerCompare(
      MethodHandle method, Object alwaysNull, Object[] arguments, int hookId) {
    TraceDataFlowNativeCallbacks.traceCmpInt(
        ((Number) arguments[0]).intValue(), ((Number) arguments[1]).intValue(), hookId);
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.lang.Byte",
      targetMethod = "compareTo",
      targetMethodDescriptor = "(Ljava/lang/Byte;)I")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.lang.Short",
      targetMethod = "compareTo",
      targetMethodDescriptor = "(Ljava/lang/Short;)I")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.lang.Integer",
      targetMethod = "compareTo",
      targetMethodDescriptor = "(Ljava/lang/Integer;)I")
  public static void integerCompareTo(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    TraceDataFlowNativeCallbacks.traceCmpInt(
        ((Number) thisObject).intValue(), ((Number) arguments[0]).intValue(), hookId);
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.lang.Long",
      targetMethod = "compare",
      targetMethodDescriptor = "(JJ)I")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.lang.Long",
      targetMethod = "compareUnsigned",
      targetMethodDescriptor = "(JJ)I")
  public static void longCompare(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    TraceDataFlowNativeCallbacks.traceCmpLong((long) arguments[0], (long) arguments[1], hookId);
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "clojure.lang.Numbers",
      targetMethod = "lt",
      targetMethodDescriptor = "(Ljava/lang/Object;Ljava/lang/Object;)Z")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "clojure.lang.Numbers",
      targetMethod = "gt",
      targetMethodDescriptor = "(Ljava/lang/Object;Ljava/lang/Object;)Z")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "clojure.lang.Numbers",
      targetMethod = "lte",
      targetMethodDescriptor = "(Ljava/lang/Object;Ljava/lang/Object;)Z")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "clojure.lang.Numbers",
      targetMethod = "gte",
      targetMethodDescriptor = "(Ljava/lang/Object;Ljava/lang/Object;)Z")
  public static void numberCompare(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    // Clojure unconditionally casts the arguments to Number.
    // https://github.com/clojure/clojure/blob/2a058814e5fa3e8fb630ae507c3fa7dc865138c6/src/jvm/clojure/lang/Numbers.java#L253
    Number arg1 = (Number) arguments[0];
    Number arg2 = (Number) arguments[1];
    TraceDataFlowNativeCallbacks.traceCmpLong(arg1.longValue(), arg2.longValue(), hookId);
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "java.lang.Long",
      targetMethod = "compareTo",
      targetMethodDescriptor = "(Ljava/lang/Long;)I")
  public static void longCompareTo(
      MethodHandle method, Long thisObject, Object[] arguments, int hookId) {
    TraceDataFlowNativeCallbacks.traceCmpLong(thisObject, (long) arguments[0], hookId);
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "clojure.lang.Numbers",
      targetMethod = "isZero",
      targetMethodDescriptor = "(Ljava/lang/Number;)Z")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "clojure.lang.Numbers",
      targetMethod = "isPos",
      targetMethodDescriptor = "(Ljava/lang/Number;)Z")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "clojure.lang.Numbers",
      targetMethod = "isNeg",
      targetMethodDescriptor = "(Ljava/lang/Number;)Z")
  public static void staticNumberCompareZero(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    Number arg = (Number) arguments[0];
    TraceDataFlowNativeCallbacks.traceCmpLong(arg.longValue(), 0, hookId);
  }

  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = "kotlin.jvm.internal.Intrinsics ",
      targetMethod = "compare",
      targetMethodDescriptor = "(JJ)I")
  public static void longCompareKt(
      MethodHandle method, Object alwaysNull, Object[] arguments, int hookId) {
    TraceDataFlowNativeCallbacks.traceCmpLong((long) arguments[0], (long) arguments[1], hookId);
  }

  @MethodHook(type = HookType.AFTER, targetClassName = "java.lang.String", targetMethod = "equals")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.lang.String",
      targetMethod = "equalsIgnoreCase")
  public static void equals(
      MethodHandle method, String thisObject, Object[] arguments, int hookId, Boolean areEqual) {
    if (!areEqual && arguments.length == 1 && arguments[0] instanceof String) {
      // The precise value of the result of the comparison is not used by libFuzzer as long as it is
      // non-zero.
      TraceDataFlowNativeCallbacks.traceStrcmp(thisObject, (String) arguments[0], 1, hookId);
    }
  }

  @MethodHook(type = HookType.AFTER, targetClassName = "java.util.Objects", targetMethod = "equals")
  public static void genericObjectsEquals(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Boolean areEqual) {
    if (!areEqual
        && arguments.length == 2
        && arguments[0] != null
        && arguments[1] != null
        && arguments[0].getClass() == arguments[1].getClass()) {
      TraceDataFlowNativeCallbacks.traceGenericCmp(arguments[0], arguments[1], hookId);
    }
  }

  @MethodHook(type = HookType.AFTER, targetClassName = "java.lang.Object", targetMethod = "equals")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.lang.CharSequence",
      targetMethod = "equals")
  @MethodHook(type = HookType.AFTER, targetClassName = "java.lang.Number", targetMethod = "equals")
  public static void genericEquals(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Boolean areEqual) {
    if (!areEqual
        && arguments.length == 1
        && arguments[0] != null
        && thisObject.getClass() == arguments[0].getClass()) {
      TraceDataFlowNativeCallbacks.traceGenericCmp(thisObject, arguments[0], hookId);
    }
  }

  @MethodHook(type = HookType.AFTER, targetClassName = "clojure.lang.Util", targetMethod = "equiv")
  public static void genericStaticEquals(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Boolean areEqual) {
    if (!areEqual
        && arguments.length == 2
        && arguments[0] != null
        && arguments[1] != null
        && arguments[1].getClass() == arguments[0].getClass()) {
      TraceDataFlowNativeCallbacks.traceGenericCmp(arguments[0], arguments[1], hookId);
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "clojure.lang.Util",
      targetMethod = "compare",
      targetMethodDescriptor = "(Ljava/lang/Object;Ljava/lang/Object;)I")
  public static void genericStaticCompareTo(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Integer result) {
    if (result != 0
        && arguments.length == 2
        && arguments[0] != null
        && arguments[1] != null
        && arguments[1].getClass() == arguments[0].getClass()) {
      TraceDataFlowNativeCallbacks.traceGenericCmp(arguments[0], arguments[1], hookId);
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.lang.String",
      targetMethod = "compareTo")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.lang.String",
      targetMethod = "compareToIgnoreCase")
  public static void compareTo(
      MethodHandle method, String thisObject, Object[] arguments, int hookId, Integer returnValue) {
    if (returnValue != 0 && arguments.length == 1 && arguments[0] instanceof String) {
      TraceDataFlowNativeCallbacks.traceStrcmp(
          thisObject, (String) arguments[0], returnValue, hookId);
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.lang.String",
      targetMethod = "contentEquals")
  public static void contentEquals(
      MethodHandle method,
      String thisObject,
      Object[] arguments,
      int hookId,
      Boolean areEqualContents) {
    if (!areEqualContents && arguments.length == 1 && arguments[0] instanceof CharSequence) {
      TraceDataFlowNativeCallbacks.traceStrcmp(
          thisObject, ((CharSequence) arguments[0]).toString(), 1, hookId);
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.lang.String",
      targetMethod = "regionMatches",
      targetMethodDescriptor = "(ZILjava/lang/String;II)Z")
  public static void regionsMatches5(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Boolean returnValue) {
    if (!returnValue) {
      int toffset = (int) arguments[1];
      String other = (String) arguments[2];
      int ooffset = (int) arguments[3];
      int len = (int) arguments[4];
      regionMatchesInternal((String) thisObject, toffset, other, ooffset, len, hookId);
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.lang.String",
      targetMethod = "regionMatches",
      targetMethodDescriptor = "(ILjava/lang/String;II)Z")
  public static void regionMatches4(
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
    if (toffset < 0 || ooffset < 0) return;
    int cappedThisStringEnd = Math.min(toffset + len, thisString.length());
    int cappedOtherStringEnd = Math.min(ooffset + len, other.length());
    String thisPart = thisString.substring(toffset, cappedThisStringEnd);
    String otherPart = other.substring(ooffset, cappedOtherStringEnd);
    TraceDataFlowNativeCallbacks.traceStrcmp(thisPart, otherPart, 1, hookId);
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.lang.String",
      targetMethod = "contains")
  public static void contains(
      MethodHandle method, String thisObject, Object[] arguments, int hookId, Boolean doesContain) {
    if (!doesContain && arguments.length == 1 && arguments[0] instanceof CharSequence) {
      TraceDataFlowNativeCallbacks.traceStrstr(
          thisObject, ((CharSequence) arguments[0]).toString(), hookId);
    }
  }

  @MethodHook(type = HookType.AFTER, targetClassName = "java.lang.String", targetMethod = "indexOf")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.lang.String",
      targetMethod = "lastIndexOf")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.lang.StringBuffer",
      targetMethod = "indexOf")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.lang.StringBuffer",
      targetMethod = "lastIndexOf")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.lang.StringBuilder",
      targetMethod = "indexOf")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.lang.StringBuilder",
      targetMethod = "lastIndexOf")
  public static void indexOf(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Integer returnValue) {
    if (returnValue == -1 && arguments.length >= 1 && arguments[0] instanceof String) {
      TraceDataFlowNativeCallbacks.traceStrstr(
          thisObject.toString(), (String) arguments[0], hookId);
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.lang.String",
      targetMethod = "startsWith")
  public static void startsWith(
      MethodHandle method,
      String thisObject,
      Object[] arguments,
      int hookId,
      Boolean doesStartWith) {
    if (!doesStartWith && arguments.length >= 1 && arguments[0] instanceof String) {
      String needle = (String) arguments[0];
      String haystack = thisObject.substring(0, Math.min(thisObject.length(), needle.length()));
      TraceDataFlowNativeCallbacks.traceStrcmp(haystack, needle, 1, hookId);
      TraceDataFlowNativeCallbacks.traceStrstr(thisObject, needle, 31 * hookId + 11);
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.lang.String",
      targetMethod = "endsWith")
  public static void endsWith(
      MethodHandle method, String thisObject, Object[] arguments, int hookId, Boolean doesEndWith) {
    if (!doesEndWith && arguments.length >= 1 && arguments[0] instanceof String) {
      String needle = (String) arguments[0];
      String haystack = thisObject.substring(Math.min(thisObject.length(), needle.length()));
      TraceDataFlowNativeCallbacks.traceStrcmp(haystack, needle, 1, hookId);
      TraceDataFlowNativeCallbacks.traceStrstr(thisObject, needle, 31 * hookId + 11);
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.lang.String",
      targetMethod = "replace",
      targetMethodDescriptor =
          "(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;")
  public static void replace(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, String returnValue) {
    String original = (String) thisObject;
    // Report only if the replacement was not successful.
    if (original.equals(returnValue)) {
      String target = arguments[0].toString();
      TraceDataFlowNativeCallbacks.traceStrstr(original, target, hookId);
    }
  }

  // For standard Kotlin packages, which are named according to the pattern kotlin.*, we append a
  // whitespace to the package name of the target class so that they are not mangled due to shading.
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.jvm.internal.Intrinsics ",
      targetMethod = "areEqual")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "equals")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "equals$default")
  public static void equalsKt(
      MethodHandle method,
      Object alwaysNull,
      Object[] arguments,
      int hookId,
      Boolean equalStrings) {
    if (!equalStrings
        && arguments.length >= 2
        && arguments[0] instanceof String
        && arguments[1] instanceof String) {
      TraceDataFlowNativeCallbacks.traceStrcmp(
          (String) arguments[0], (String) arguments[1], 1, hookId);
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "contentEquals")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "contentEquals$default")
  public static void contentEqualKt(
      MethodHandle method,
      Object alwaysNull,
      Object[] arguments,
      int hookId,
      Boolean equalStrings) {
    if (!equalStrings
        && arguments.length >= 2
        && arguments[0] instanceof CharSequence
        && arguments[1] instanceof CharSequence) {
      TraceDataFlowNativeCallbacks.traceStrcmp(
          arguments[0].toString(), arguments[1].toString(), 1, hookId);
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "compareTo")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "compareTo$default")
  public static void compareToKt(
      MethodHandle method, Object alwaysNull, Object[] arguments, int hookId, Integer returnValue) {
    if (returnValue != 0
        && arguments.length >= 2
        && arguments[0] instanceof String
        && arguments[1] instanceof String) {
      TraceDataFlowNativeCallbacks.traceStrcmp(
          (String) arguments[0], (String) arguments[1], 1, hookId);
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "startsWith")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "startsWith$default")
  public static void startsWithKt(
      MethodHandle method,
      Object alwaysNull,
      Object[] arguments,
      int hookId,
      Boolean doesStartsWith) {
    if (!doesStartsWith
        && arguments.length >= 2
        && arguments[0] instanceof CharSequence
        && arguments[1] instanceof CharSequence) {
      String target = ((CharSequence) arguments[0]).toString();
      String needle = ((CharSequence) arguments[1]).toString();
      String haystack = target.substring(0, Math.min(target.length(), needle.length()));
      TraceDataFlowNativeCallbacks.traceStrcmp(haystack, needle, 1, hookId);
      TraceDataFlowNativeCallbacks.traceStrstr(target, needle, 31 * hookId + 11);
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "endsWith")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "endsWith$default")
  public static void endsWithKt(
      MethodHandle method,
      Object alwaysNull,
      Object[] arguments,
      int hookId,
      Boolean doesEndsWith) {
    if (!doesEndsWith
        && arguments.length >= 2
        && arguments[0] instanceof CharSequence
        && arguments[1] instanceof CharSequence) {
      String target = ((CharSequence) arguments[0]).toString();
      String needle = ((CharSequence) arguments[1]).toString();
      String haystack = target.substring(Math.min(target.length(), needle.length()));
      TraceDataFlowNativeCallbacks.traceStrcmp(haystack, needle, 1, hookId);
      TraceDataFlowNativeCallbacks.traceStrstr(target, needle, 31 * hookId + 11);
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "contains")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "contains$default")
  public static void containsKt(
      MethodHandle method, Object alwaysNull, Object[] arguments, int hookId, Boolean doesContain) {
    if (!doesContain
        && arguments.length >= 2
        && arguments[0] instanceof CharSequence
        && arguments[1] instanceof CharSequence) {
      TraceDataFlowNativeCallbacks.traceStrstr(
          arguments[0].toString(), arguments[1].toString(), hookId);
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "indexOf")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "indexOf$default")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "lastIndexOf")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "lastIndexOf$default")
  public static void indexOfKt(
      MethodHandle method, Object alwaysNull, Object[] arguments, int hookId, Integer returnValue) {
    if (returnValue != -1 || arguments.length < 2 || !(arguments[0] instanceof CharSequence)) {
      return;
    }
    if (arguments[1] instanceof String) {
      TraceDataFlowNativeCallbacks.traceStrstr(
          arguments[0].toString(), (String) arguments[1], hookId);
    } else if (arguments[1] instanceof Character) {
      TraceDataFlowNativeCallbacks.traceStrstr(
          arguments[0].toString(), ((Character) arguments[1]).toString(), hookId);
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "replace")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "replace$default")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "replaceAfter")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "replaceAfter$default")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "replaceAfterLast")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "replaceAfterLast$default")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "replaceBefore")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "replaceBefore$default")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "replaceBeforeLast")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "replaceBeforeLast$default")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "replaceFirst")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "replaceFirst$default")
  public static void replaceKt(
      MethodHandle method, Object alwaysNull, Object[] arguments, int hookId, String returnValue) {
    if (arguments.length < 2 || !(arguments[0] instanceof String)) {
      return;
    }
    String original = (String) arguments[0];
    if (!original.equals(returnValue)) {
      return;
    }

    // We currently don't handle the overloads that take a regex as a second argument.
    if (arguments[1] instanceof String || arguments[1] instanceof Character) {
      TraceDataFlowNativeCallbacks.traceStrstr(original, arguments[1].toString(), hookId);
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "regionMatches",
      targetMethodDescriptor = "(Ljava/lang/String;ILjava/lang/String;IIZ)Z")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "regionMatches$default",
      targetMethodDescriptor = "(Ljava/lang/String;ILjava/lang/String;IIZILjava/lang/Object;)Z")
  public static void regionMatchesKt(
      MethodHandle method,
      Object alwaysNull,
      Object[] arguments,
      int hookId,
      Boolean doesRegionMatch) {
    if (!doesRegionMatch) {
      String thisString = arguments[0].toString();
      int thisOffset = (int) arguments[1];
      String other = arguments[2].toString();
      int otherOffset = (int) arguments[3];
      int length = (int) arguments[4];
      regionMatchesInternal(thisString, thisOffset, other, otherOffset, length, hookId);
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "indexOfAny")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "indexOfAny$default")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "lastIndexOfAny")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "lastIndexOfAny$default")
  public static void indexOfAnyKt(
      MethodHandle method, Object alwaysNull, Object[] arguments, int hookId, Integer returnValue) {
    if (returnValue == -1 && arguments.length >= 2 && arguments[0] instanceof CharSequence) {
      guideTowardContainmentOfFirstElement(arguments[0].toString(), arguments[1], hookId);
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "findAnyOf")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "findAnyOf$default")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "findLastAnyOf")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "kotlin.text.StringsKt ",
      targetMethod = "findLastAnyOf$default")
  public static void findAnyKt(
      MethodHandle method, Object alwaysNull, Object[] arguments, int hookId, Object returnValue) {
    if (returnValue == null && arguments.length >= 2 && arguments[0] instanceof CharSequence) {
      guideTowardContainmentOfFirstElement(arguments[0].toString(), arguments[1], hookId);
    }
  }

  private static void guideTowardContainmentOfFirstElement(
      String containingString, Object candidateCollectionObj, int hookId) {
    if (candidateCollectionObj instanceof Collection<?>) {
      Collection<?> strings = (Collection<?>) candidateCollectionObj;
      if (strings.isEmpty()) {
        return;
      }
      Object firstElementObj = strings.iterator().next();
      if (firstElementObj instanceof CharSequence) {
        TraceDataFlowNativeCallbacks.traceStrstr(
            containingString, firstElementObj.toString(), hookId);
      }
    } else if (candidateCollectionObj.getClass().isArray()) {
      if (candidateCollectionObj.getClass().getComponentType() == char.class) {
        char[] chars = (char[]) candidateCollectionObj;
        if (chars.length > 0) {
          TraceDataFlowNativeCallbacks.traceStrstr(
              containingString, Character.toString(chars[0]), hookId);
        }
      }
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.Arrays",
      targetMethod = "equals",
      targetMethodDescriptor = "([B[B)Z")
  public static void arraysEquals(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Boolean returnValue) {
    if (returnValue) return;
    byte[] first = (byte[]) arguments[0];
    byte[] second = (byte[]) arguments[1];
    TraceDataFlowNativeCallbacks.traceMemcmp(first, second, 1, hookId);
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.Arrays",
      targetMethod = "equals",
      targetMethodDescriptor = "([BII[BII)Z")
  public static void arraysEqualsRange(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Boolean returnValue) {
    if (returnValue) return;
    byte[] first =
        Arrays.copyOfRange((byte[]) arguments[0], (int) arguments[1], (int) arguments[2]);
    byte[] second =
        Arrays.copyOfRange((byte[]) arguments[3], (int) arguments[4], (int) arguments[5]);
    TraceDataFlowNativeCallbacks.traceMemcmp(first, second, 1, hookId);
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.Arrays",
      targetMethod = "compare",
      targetMethodDescriptor = "([B[B)I")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.Arrays",
      targetMethod = "compareUnsigned",
      targetMethodDescriptor = "([B[B)I")
  public static void arraysCompare(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Integer returnValue) {
    if (returnValue == 0) return;
    byte[] first = (byte[]) arguments[0];
    byte[] second = (byte[]) arguments[1];
    TraceDataFlowNativeCallbacks.traceMemcmp(first, second, returnValue, hookId);
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.Arrays",
      targetMethod = "compare",
      targetMethodDescriptor = "([BII[BII)I")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.Arrays",
      targetMethod = "compareUnsigned",
      targetMethodDescriptor = "([BII[BII)I")
  public static void arraysCompareRange(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Integer returnValue) {
    if (returnValue == 0) return;
    byte[] first =
        Arrays.copyOfRange((byte[]) arguments[0], (int) arguments[1], (int) arguments[2]);
    byte[] second =
        Arrays.copyOfRange((byte[]) arguments[3], (int) arguments[4], (int) arguments[5]);
    TraceDataFlowNativeCallbacks.traceMemcmp(first, second, returnValue, hookId);
  }

  // The maximal number of elements of a non-TreeMap Map that will be sorted and searched for the
  // key closest to the current lookup key in the mapGet hook.
  private static final int MAX_NUM_KEYS_TO_ENUMERATE = 100;

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.Map",
      targetMethod = "containsKey",
      targetMethodDescriptor = "(Ljava/lang/Object;)Z")
  public static void containsKey(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Boolean isContained) {
    if (!isContained) {
      mapHookInternal((Map) thisObject, arguments[0], hookId);
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.Map",
      targetMethod = "get",
      targetMethodDescriptor = "(Ljava/lang/Object;)Ljava/lang/Object;")
  public static void mapGet(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Object value) {
    if (value == null) {
      mapHookInternal((Map) thisObject, arguments[0], hookId);
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "java.util.Map",
      targetMethod = "getOrDefault",
      targetMethodDescriptor = "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;")
  public static void mapGetOrDefault(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId, Object value) {
    Object defaultValue = arguments[1];
    if (value == defaultValue) {
      mapHookInternal((Map) thisObject, arguments[0], hookId);
    }
  }

  @SuppressWarnings({"rawtypes", "unchecked"})
  private static <K, V> void mapHookInternal(Map<K, V> map, K currentKey, int hookId) {
    if (map == null || map.isEmpty()) return;
    if (currentKey == null) return;
    // Find two valid map keys that bracket currentKey.
    // This is a generalization of libFuzzer's __sanitizer_cov_trace_switch:
    // https://github.com/llvm/llvm-project/blob/318942de229beb3b2587df09e776a50327b5cef0/compiler-rt/lib/fuzzer/FuzzerTracePC.cpp#L564
    Object lowerBoundKey = null;
    Object upperBoundKey = null;
    try {
      if (map instanceof TreeMap) {
        final TreeMap<K, V> treeMap = (TreeMap<K, V>) map;
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
          if (!(validKey instanceof Comparable)) continue;
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
          if (enumeratedKeys++ > MAX_NUM_KEYS_TO_ENUMERATE) break;
        }
      }
    } catch (ConcurrentModificationException ignored) {
      // map was modified by another thread, skip this invocation
      return;
    }
    // Modify the hook ID so that compares against distinct valid keys are traced separately.
    if (lowerBoundKey != null) {
      TraceDataFlowNativeCallbacks.traceGenericCmp(currentKey, lowerBoundKey, hookId);
    }
    if (upperBoundKey != null) {
      TraceDataFlowNativeCallbacks.traceGenericCmp(currentKey, upperBoundKey, 31 * hookId + 11);
    }
  }

  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "org.junit.jupiter.api.Assertions",
      targetMethod = "assertNotEquals",
      targetMethodDescriptor = "(Ljava/lang/Object;Ljava/lang/Object;)V")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "org.junit.jupiter.api.Assertions",
      targetMethod = "assertNotEquals",
      targetMethodDescriptor = "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V")
  @MethodHook(
      type = HookType.AFTER,
      targetClassName = "org.junit.jupiter.api.Assertions",
      targetMethod = "assertNotEquals",
      targetMethodDescriptor =
          "(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/function/Supplier;)V")
  public static void assertEquals(
      MethodHandle method, Object node, Object[] args, int hookId, Object alwaysNull) {
    if (args[0] != null && args[1] != null && args[0].getClass() == args[1].getClass()) {
      TraceDataFlowNativeCallbacks.traceGenericCmp(args[0], args[1], hookId);
    }
  }
}
