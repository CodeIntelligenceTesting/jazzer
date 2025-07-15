/*
 * Copyright 2025 Code Intelligence GmbH
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
package com.code_intelligence.jazzer.sanitizers;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.api.MethodHook;
import com.code_intelligence.jazzer.utils.UnsafeProvider;
import java.lang.invoke.MethodHandle;
import java.lang.reflect.Array;
import sun.misc.Unsafe;

/** Sanitizer for {@link Unsafe sun.misc.Unsafe} usage. */
public class UnsafeSanitizer {
  /*
   * Implementation notes:
   * - This only covers the 'public' class sun.misc.Unsafe, not the JDK-internal jdk.internal.misc.Unsafe since
   *   it is rather unlikely that user code uses that, especially with strong encapsulation of JDK internals (JEP 403)
   * - This only covers Unsafe access for arrays:
   *   - Array access can be implemented in a stateless way because all information is available from the arguments
   *     passed to the Unsafe method
   *   - Sanitizing field access is probably not interesting because that is normally performed with hardcoded
   *     offsets, which cannot be influenced by fuzzing input data
   *   - Sanitizing native memory access would require keeping track of allocations, and is therefore due to its
   *     complexity out of scope for now
   * - Alignment when reading a primitive value larger than 1 byte (e.g. an 8-byte long) from a primitive array of
   *   smaller element size is not checked
   *   It depends on the platform where the application is running whether unaligned access is supported, but many
   *   applications using Unsafe assume that unaligned access is supported.
   * - Where necessary the hooks use `@MethodHook#targetMethodDescriptor` to select the Unsafe method overload
   *   with Object parameter, instead of the overload without Object parameter which only supports native memory access.
   */

  private static final Unsafe UNSAFE = UnsafeProvider.getUnsafe();
  private static final String UNSAFE_NAME = "sun.misc.Unsafe";

  /*
  Script for generating the @MethodHook annotations:
  ====================================================
   Method[] methods = sun.misc.Unsafe.class.getMethods();
   Set<String> methodsWithNativeOnlyOverload = Arrays.stream(methods)
     .filter(m -> Arrays.stream(m.getParameterTypes()).noneMatch(p -> p == Object.class))
     .map(Method::getName)
     .collect(Collectors.toSet());

   Set<String> emittedWithoutDesc = new HashSet<>();
   Arrays.stream(methods)
     .filter(m -> Arrays.stream(m.getParameterTypes()).anyMatch(p -> p == Object.class))
     .filter(m -> !Arrays.asList("equals", "monitorEnter", "monitorExit", "tryMonitorEnter", "unpark")
       .contains(m.getName()))
     .sorted(Comparator.comparing(Method::getName))
     .forEach(m -> {
       String methodName = m.getName();
       String s = "@MethodHook(\n    type = HookType.BEFORE,\n    targetClassName = UNSAFE_NAME,\n    targetMethod = \""
           + methodName
           + "\"";
       if (methodsWithNativeOnlyOverload.contains(methodName)) {
         String methodDesc;
         try {
           methodDesc = MethodHandles.lookup().unreflect(m).type()
               // Drop receiver type (i.e. `Unsafe this`)
               .dropParameterTypes(0, 1)
               .toMethodDescriptorString();
         } catch (IllegalAccessException e) {
           throw new RuntimeException(e);
         }
         s += ",\n    targetMethodDescriptor = \""
             + methodDesc
             + "\"";
         System.out.println(s + ")");
       }
       // Avoid emitting same annotation twice for overloads where no native-only overload exists
       else if (emittedWithoutDesc.add(methodName)) {
         System.out.println(s + ")");
       }
     });
   ====================================================
  */

  private static int getBytesCount(Class<?> c) {
    int bytesCount;
    if (c == boolean.class) {
      // Assumes that `Unsafe.ARRAY_BOOLEAN_INDEX_SCALE > 0`
      bytesCount = 1;
    } else if (c == byte.class) {
      bytesCount = 1;
    } else if (c == char.class || c == short.class) {
      bytesCount = 2;
    } else if (c == int.class || c == float.class) {
      bytesCount = 4;
    } else if (c == long.class || c == double.class) {
      bytesCount = 8;
    } else {
      throw new AssertionError("Unexpected type: " + c);
    }
    return bytesCount;
  }

  /** Hook for all {@link Unsafe} methods which read or write an {@code Object} reference. */
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "compareAndSwapObject")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getAndSetObject")
  @MethodHook(type = HookType.BEFORE, targetClassName = UNSAFE_NAME, targetMethod = "getObject")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getObjectVolatile")
  @MethodHook(type = HookType.BEFORE, targetClassName = UNSAFE_NAME, targetMethod = "putObject")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putObjectVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putOrderedObject")
  public static void objectAccessHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    checkObjectSizedAccess(arguments);
  }

  /**
   * Hook for all {@link Unsafe} {@code get...} primitive methods, where the access size can be
   * derived from the return type.
   */
  @MethodHook(type = HookType.BEFORE, targetClassName = UNSAFE_NAME, targetMethod = "getAndAddInt")
  @MethodHook(type = HookType.BEFORE, targetClassName = UNSAFE_NAME, targetMethod = "getAndAddLong")
  @MethodHook(type = HookType.BEFORE, targetClassName = UNSAFE_NAME, targetMethod = "getAndSetInt")
  @MethodHook(type = HookType.BEFORE, targetClassName = UNSAFE_NAME, targetMethod = "getAndSetLong")
  // `getBoolean` has no overload without Object parameter, so no need to specify method descriptor
  @MethodHook(type = HookType.BEFORE, targetClassName = UNSAFE_NAME, targetMethod = "getBoolean")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getBooleanVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getByte",
      targetMethodDescriptor = "(Ljava/lang/Object;J)B")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getByte",
      // Overload with `int offset`, removed in Java 9
      targetMethodDescriptor = "(Ljava/lang/Object;I)B")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getByteVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getChar",
      targetMethodDescriptor = "(Ljava/lang/Object;J)C")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getChar",
      // Overload with `int offset`, removed in Java 9
      targetMethodDescriptor = "(Ljava/lang/Object;I)C")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getCharVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getDouble",
      targetMethodDescriptor = "(Ljava/lang/Object;J)D")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getDouble",
      // Overload with `int offset`, removed in Java 9
      targetMethodDescriptor = "(Ljava/lang/Object;I)D")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getDoubleVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getFloat",
      targetMethodDescriptor = "(Ljava/lang/Object;J)F")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getFloat",
      // Overload with `int offset`, removed in Java 9
      targetMethodDescriptor = "(Ljava/lang/Object;I)F")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getFloatVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getInt",
      targetMethodDescriptor = "(Ljava/lang/Object;J)I")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getInt",
      // Overload with `int offset`, removed in Java 9
      targetMethodDescriptor = "(Ljava/lang/Object;I)I")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getIntVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getLong",
      targetMethodDescriptor = "(Ljava/lang/Object;J)J")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getLong",
      // Overload with `int offset`, removed in Java 9
      targetMethodDescriptor = "(Ljava/lang/Object;I)J")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getLongVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getShort",
      targetMethodDescriptor = "(Ljava/lang/Object;J)S")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getShort",
      // Overload with `int offset`, removed in Java 9
      targetMethodDescriptor = "(Ljava/lang/Object;I)S")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getShortVolatile")
  public static void primitiveGetterHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    int accessSize = getBytesCount(method.type().returnType());
    checkPrimitiveAccess(arguments, accessSize);
  }

  /**
   * Hook for all {@link Unsafe} {@code compareAndSwap...} and {@code put...} primitive methods,
   * where the access size can be derived from the parameter type at index 2 (0-based).
   */
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "compareAndSwapInt")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "compareAndSwapLong")
  // `putBoolean` has no overload without Object parameter, so no need to specify method descriptor
  @MethodHook(type = HookType.BEFORE, targetClassName = UNSAFE_NAME, targetMethod = "putBoolean")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putBooleanVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putByte",
      targetMethodDescriptor = "(Ljava/lang/Object;JB)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putByte",
      // Overload with `int offset`, removed in Java 9
      targetMethodDescriptor = "(Ljava/lang/Object;IB)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putByteVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putChar",
      targetMethodDescriptor = "(Ljava/lang/Object;JC)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putChar",
      // Overload with `int offset`, removed in Java 9
      targetMethodDescriptor = "(Ljava/lang/Object;IC)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putCharVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putDouble",
      targetMethodDescriptor = "(Ljava/lang/Object;JD)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putDouble",
      // Overload with `int offset`, removed in Java 9
      targetMethodDescriptor = "(Ljava/lang/Object;ID)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putDoubleVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putFloat",
      targetMethodDescriptor = "(Ljava/lang/Object;JF)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putFloat",
      // Overload with `int offset`, removed in Java 9
      targetMethodDescriptor = "(Ljava/lang/Object;IF)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putFloatVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putInt",
      targetMethodDescriptor = "(Ljava/lang/Object;JI)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putInt",
      // Overload with `int offset`, removed in Java 9
      targetMethodDescriptor = "(Ljava/lang/Object;II)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putIntVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putLong",
      targetMethodDescriptor = "(Ljava/lang/Object;JJ)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putLong",
      // Overload with `int offset`, removed in Java 9
      targetMethodDescriptor = "(Ljava/lang/Object;IJ)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putLongVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putShort",
      targetMethodDescriptor = "(Ljava/lang/Object;JS)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putShort",
      // Overload with `int offset`, removed in Java 9
      targetMethodDescriptor = "(Ljava/lang/Object;IS)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putShortVolatile")
  @MethodHook(type = HookType.BEFORE, targetClassName = UNSAFE_NAME, targetMethod = "putOrderedInt")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putOrderedLong")
  public static void primitiveSetterHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    int accessSize =
        getBytesCount(method.type().parameterType(2 + 1)); // + 1 for implicit Unsafe instance
    checkPrimitiveAccess(arguments, accessSize);
  }

  /** Hook for {@link Unsafe#setMemory(Object, long, long, byte)} */
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "setMemory",
      // Only handle overload with Object parameter
      targetMethodDescriptor = "(Ljava/lang/Object;JJB)V")
  public static void setMemoryHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    checkPrimitiveAccess(arguments[0], (long) arguments[1], (long) arguments[2]);
  }

  /** Hook for {@link Unsafe#copyMemory(Object, long, Object, long, long)} */
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "copyMemory",
      // Only handle overload with Object parameters
      targetMethodDescriptor = "(Ljava/lang/Object;JLjava/lang/Object;JJ)V")
  public static void copyMemoryHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    long size = (long) arguments[4];
    checkPrimitiveAccess(arguments[0], (long) arguments[1], size);
    checkPrimitiveAccess(arguments[2], (long) arguments[3], size);
  }

  private static void report(String message) {
    Jazzer.reportFindingFromHook(new FuzzerSecurityIssueCritical(message));
  }

  private static long offsetValue(Object obj) {
    // Java 8 also had deprecated Unsafe method overloads with `int offset` parameter, therefore
    // cannot just cast to `long` here
    return ((Number) obj).longValue();
  }

  private static void checkPrimitiveAccess(Object[] args, long accessSize) {
    Object obj = args[0];
    long offset = offsetValue(args[1]);
    checkPrimitiveAccess(obj, offset, accessSize);
  }

  private static void checkPrimitiveAccess(Object obj, long offset, long accessSize) {
    checkAccess(obj, offset, accessSize, false);
  }

  private static void checkObjectSizedAccess(Object[] args) {
    Object obj = args[0];
    long offset = offsetValue(args[1]);
    long accessSize = Unsafe.ARRAY_OBJECT_INDEX_SCALE;
    checkAccess(obj, offset, accessSize, true);
  }

  /**
   * Checks {@link Unsafe} memory access.
   *
   * @param obj the base object for memory access; e.g. for {@link Unsafe#getInt(Object, long)} it
   *     is the argument at index 0
   * @param offset the offset for the memory access; e.g. for {@link Unsafe#getInt(Object, long)} it
   *     is the argument at index 1
   * @param accessSize the number of bytes which is accessed; e.g. for {@link Unsafe#getInt(Object,
   *     long)} it is 4 (due to {@code int} being 4 bytes large)
   * @param isObjectAccess whether an object reference (instead of a primitive value) is being
   *     accessed
   */
  private static void checkAccess(
      Object obj, long offset, long accessSize, boolean isObjectAccess) {
    if (accessSize < 0) {
      report("Negative access size: " + accessSize);
    }

    if (obj == null) {
      // Native memory access; not sanitized here
      return;
    }

    Class<?> objClass = obj.getClass();
    Class<?> componentType = objClass.getComponentType();
    if (componentType == null) {
      // Not an array
      return;
    }

    // Mixing up bytes and object references (e.g. reading an object reference from a primitive
    // array)
    // seems error-prone and might mess with the garbage collector
    if (isObjectAccess) {
      if (componentType.isPrimitive()) {
        report("Reading or writing object reference from a " + objClass.getTypeName());
      }
    } else {
      if (!componentType.isPrimitive()) {
        report("Reading or writing bytes from a " + objClass.getTypeName());
      }
    }

    long baseOffset = UNSAFE.arrayBaseOffset(objClass);
    long indexScale = UNSAFE.arrayIndexScale(objClass);

    if (offset < baseOffset) {
      report("Offset " + offset + " is lower than baseOffset " + baseOffset);
    }
    long endOffset = baseOffset + Array.getLength(obj) * indexScale;
    // Uses `compareUnsigned` to account for overflow
    if (Long.compareUnsigned(endOffset, offset + accessSize) < 0) {
      report(
          "Access at offset "
              + offset
              + " with size "
              + accessSize
              + " exceeds end offset "
              + endOffset);
    }

    if (isObjectAccess && (offset - baseOffset) % indexScale != 0) {
      // Trying to read or write object at an offset which spans two array elements
      report("Access at offset " + offset + " is not aligned");
    }
    // For primitive arrays don't check if access is aligned; depends on platform if unaligned
    // access is supported and some libraries which are using Unsafe assume that it is supported
  }
}
