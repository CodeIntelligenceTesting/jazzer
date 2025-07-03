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

/**
 * Sanitizer for {@link Unsafe sun.misc.Unsafe} usage which performs out-of-bounds and some other
 * invalid access on arrays.
 */
public class UnsafeArrayOutOfBounds {
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
   Set<String> allMethodNames = new HashSet<>();
   Set<String> duplicateMethodNames = new HashSet<>();
   Arrays.stream(methods).map(Method::getName).forEach(n -> {
     if (!allMethodNames.add(n)) {
       duplicateMethodNames.add(n);
     }
   });

   Arrays.stream(methods)
     .filter(m -> Arrays.stream(m.getParameterTypes()).anyMatch(p -> p == Object.class))
     .filter(m -> !Set.of("equals", "unpark").contains(m.getName()))
     .sorted(Comparator.comparing(Method::getName))
     .forEach(m -> {
       String methodName = m.getName();
       String s = "@MethodHook(\n    type = HookType.BEFORE,\n    targetClassName = UNSAFE_NAME,\n    targetMethod = \""
           + methodName
           + "\"";
       if (duplicateMethodNames.contains(methodName)) {
         String methodDesc;
         try {
           methodDesc = MethodHandles.lookup().unreflect(m).type().toMethodDescriptorString();
         } catch (IllegalAccessException e) {
           throw new RuntimeException(e);
         }
         s += ",\n    targetMethodDescriptor = \""
             + methodDesc
             + "\"";
       }
       System.out.println(s + ")");
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
  @MethodHook(type = HookType.BEFORE, targetClassName = UNSAFE_NAME, targetMethod = "getBoolean")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getBooleanVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getByte",
      targetMethodDescriptor = "(Lsun/misc/Unsafe;Ljava/lang/Object;J)B")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getByteVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getChar",
      targetMethodDescriptor = "(Lsun/misc/Unsafe;Ljava/lang/Object;J)C")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getCharVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getDouble",
      targetMethodDescriptor = "(Lsun/misc/Unsafe;Ljava/lang/Object;J)D")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getDoubleVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getFloat",
      targetMethodDescriptor = "(Lsun/misc/Unsafe;Ljava/lang/Object;J)F")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getFloatVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getInt",
      targetMethodDescriptor = "(Lsun/misc/Unsafe;Ljava/lang/Object;J)I")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getIntVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getLong",
      targetMethodDescriptor = "(Lsun/misc/Unsafe;Ljava/lang/Object;J)J")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getLongVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getShort",
      targetMethodDescriptor = "(Lsun/misc/Unsafe;Ljava/lang/Object;J)S")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "getShortVolatile")
  public static void primitiveGetterHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    int accessSize = getBytesCount(method.type().returnType());
    checkAccess(arguments, accessSize);
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
  @MethodHook(type = HookType.BEFORE, targetClassName = UNSAFE_NAME, targetMethod = "putBoolean")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putBooleanVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putByte",
      targetMethodDescriptor = "(Lsun/misc/Unsafe;Ljava/lang/Object;JB)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putByteVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putChar",
      targetMethodDescriptor = "(Lsun/misc/Unsafe;Ljava/lang/Object;JC)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putCharVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putDouble",
      targetMethodDescriptor = "(Lsun/misc/Unsafe;Ljava/lang/Object;JD)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putDoubleVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putFloat",
      targetMethodDescriptor = "(Lsun/misc/Unsafe;Ljava/lang/Object;JF)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putFloatVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putInt",
      targetMethodDescriptor = "(Lsun/misc/Unsafe;Ljava/lang/Object;JI)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putIntVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putLong",
      targetMethodDescriptor = "(Lsun/misc/Unsafe;Ljava/lang/Object;JJ)V")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putLongVolatile")
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "putShort",
      targetMethodDescriptor = "(Lsun/misc/Unsafe;Ljava/lang/Object;JS)V")
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
    checkAccess(arguments, accessSize);
  }

  /** Hook for {@link Unsafe#setMemory(Object, long, long, byte)} */
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "setMemory",
      // Only handle overload with Object parameter
      targetMethodDescriptor = "(Lsun/misc/Unsafe;Ljava/lang/Object;JJB)V")
  public static void setMemoryHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    checkAccess(arguments[0], (long) arguments[1], (long) arguments[2]);
  }

  /** Hook for {@link Unsafe#copyMemory(Object, long, Object, long, long)} */
  @MethodHook(
      type = HookType.BEFORE,
      targetClassName = UNSAFE_NAME,
      targetMethod = "copyMemory",
      // Only handle overload with Object parameters
      targetMethodDescriptor = "(Lsun/misc/Unsafe;Ljava/lang/Object;JLjava/lang/Object;JJ)V")
  public static void copyMemoryHook(
      MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
    long size = (long) arguments[4];
    checkAccess(arguments[0], (long) arguments[1], size);
    checkAccess(arguments[2], (long) arguments[3], size);
  }

  private static void report(String message) {
    Jazzer.reportFindingFromHook(new FuzzerSecurityIssueCritical(message));
  }

  private static void checkAccess(Object[] args, long accessSize) {
    Object obj = args[0];
    long offset = (long) args[1];
    checkAccess(obj, offset, accessSize);
  }

  /**
   * Checks {@link Unsafe} memory access where the access size is measured in number of bytes.
   *
   * @param obj the base object for memory access; e.g. for {@link Unsafe#getInt(Object, long)} it
   *     is the argument at index 0
   * @param offset the offset for the memory access; e.g. for {@link Unsafe#getInt(Object, long)} it
   *     is the argument at index 1
   * @param accessSize the number of bytes which is accessed; e.g. for {@link Unsafe#getInt(Object,
   *     long)} it is 4 (due to {@code int} being 4 bytes large)
   * @see #checkObjectSizedAccess(Object, long)
   */
  private static void checkAccess(Object obj, long offset, long accessSize) {
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

    if (!componentType.isPrimitive()) {
      // Reading or writing bytes to an array of references; might be possible but seems
      // rather unreliable and might mess with the garbage collector?
      report("Reading or writing bytes from a " + objClass.getTypeName());
    }

    long baseOffset = UNSAFE.arrayBaseOffset(objClass);
    long indexScale = UNSAFE.arrayIndexScale(objClass);

    if (offset < baseOffset) {
      report("Offset " + offset + " lower than baseOffset " + baseOffset);
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

    // Don't check if access is aligned; depends on platform if unaligned access is supported
    // and some libraries which are using Unsafe assume that it is supported
  }

  private static void checkObjectSizedAccess(Object[] args) {
    Object obj = args[0];
    long offset = (long) args[1];
    checkObjectSizedAccess(obj, offset);
  }

  /**
   * Checks {@link Unsafe} memory access where an object reference is accessed.
   *
   * @param obj the base object for memory access; e.g. for {@link Unsafe#getObject(Object, long)}
   *     it is the argument at index 0
   * @param offset the offset for the memory access; e.g. for {@link Unsafe#getObject(Object, long)}
   *     it is the argument at index 1
   * @see #checkAccess(Object, long, long)
   */
  private static void checkObjectSizedAccess(Object obj, long offset) {
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

    if (componentType.isPrimitive()) {
      // Reading or writing object references from a primitive array; might be possible but seems
      // rather unreliable and might mess with the garbage collector?
      report("Reading or writing object reference from a " + objClass.getTypeName());
    }

    long baseOffset = UNSAFE.arrayBaseOffset(objClass);
    long indexScale = UNSAFE.arrayIndexScale(objClass);

    if (offset < baseOffset) {
      report("Offset " + offset + " lower than baseOffset " + baseOffset);
    }

    if ((offset - baseOffset) % indexScale != 0) {
      // Trying to read or write object at an offset which spans two array elements
      report("Access at offset " + offset + " is not aligned");
    }

    long endOffset = baseOffset + Array.getLength(obj) * indexScale;
    long accessSize = indexScale;
    if (Long.compareUnsigned(endOffset, offset + accessSize) < 0) {
      report("Access at offset " + offset + " exceeds end offset " + endOffset);
    }
  }
}
