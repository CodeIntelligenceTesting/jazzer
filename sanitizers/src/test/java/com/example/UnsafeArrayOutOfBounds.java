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
package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import sun.misc.Unsafe;

public class UnsafeArrayOutOfBounds {
  private static final Unsafe UNSAFE;

  static {
    try {
      Field f = Unsafe.class.getDeclaredField("theUnsafe");
      f.setAccessible(true);
      UNSAFE = (Unsafe) f.get(null);
    } catch (ReflectiveOperationException e) {
      throw new RuntimeException(e);
    }
  }

  /** Defines test methods which all perform invalid memory access with {@link Unsafe}. */
  @SuppressWarnings("unused") // test methods are accessed through reflection
  private static class TestMethods {
    static void compareAndSwapInt() {
      UNSAFE.compareAndSwapInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET - 1, 0, 1);
    }

    static void compareAndSwapInt_end() {
      UNSAFE.compareAndSwapInt(
          new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 5L * Unsafe.ARRAY_INT_INDEX_SCALE, 0, 1);
    }

    static void compareAndSwapLong() {
      UNSAFE.compareAndSwapLong(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET - 1, 0, 1);
    }

    static void compareAndSwapLong_end() {
      UNSAFE.compareAndSwapLong(
          new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 5L * Unsafe.ARRAY_LONG_INDEX_SCALE, 0, 1);
    }

    static void compareAndSwapObject() {
      UNSAFE.compareAndSwapObject(new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET - 1, "a", "b");
    }

    static void compareAndSwapObject_end() {
      UNSAFE.compareAndSwapObject(
          new Object[5],
          Unsafe.ARRAY_OBJECT_BASE_OFFSET + 5L * Unsafe.ARRAY_OBJECT_INDEX_SCALE,
          "a",
          "b");
    }

    static void getAndAddInt() {
      UNSAFE.getAndAddInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET - 1, 1);
    }

    static void getAndAddInt_end() {
      UNSAFE.getAndAddInt(
          new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 5L * Unsafe.ARRAY_INT_INDEX_SCALE, 1);
    }

    static void getAndAddLong() {
      UNSAFE.getAndAddLong(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET - 1, 1);
    }

    static void getAndAddLong_end() {
      UNSAFE.getAndAddLong(
          new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 5L * Unsafe.ARRAY_LONG_INDEX_SCALE, 1);
    }

    static void getAndSetInt() {
      UNSAFE.getAndSetInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET - 1, 1);
    }

    static void getAndSetInt_end() {
      UNSAFE.getAndSetInt(
          new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 5L * Unsafe.ARRAY_INT_INDEX_SCALE, 1);
    }

    static void getAndSetLong() {
      UNSAFE.getAndSetLong(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET - 1, 1);
    }

    static void getAndSetLong_end() {
      UNSAFE.getAndSetLong(
          new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 5L * Unsafe.ARRAY_LONG_INDEX_SCALE, 1);
    }

    static void getAndSetObject() {
      UNSAFE.getAndSetObject(new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET - 1, "a");
    }

    static void getAndSetObject_end() {
      UNSAFE.getAndSetObject(
          new Object[5],
          Unsafe.ARRAY_OBJECT_BASE_OFFSET + 5L * Unsafe.ARRAY_OBJECT_INDEX_SCALE,
          "a");
    }

    static void getBoolean() {
      UNSAFE.getBoolean(new boolean[5], Unsafe.ARRAY_BOOLEAN_BASE_OFFSET - 1);
    }

    static void getBoolean_end() {
      UNSAFE.getBoolean(
          new boolean[5], Unsafe.ARRAY_BOOLEAN_BASE_OFFSET + 5L * Unsafe.ARRAY_BOOLEAN_INDEX_SCALE);
    }

    static void getBooleanVolatile() {
      UNSAFE.getBooleanVolatile(new boolean[5], Unsafe.ARRAY_BOOLEAN_BASE_OFFSET - 1);
    }

    static void getBooleanVolatile_end() {
      UNSAFE.getBooleanVolatile(
          new boolean[5], Unsafe.ARRAY_BOOLEAN_BASE_OFFSET + 5L * Unsafe.ARRAY_BOOLEAN_INDEX_SCALE);
    }

    static void getByte() {
      UNSAFE.getByte(new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET - 1);
    }

    static void getByte_end() {
      UNSAFE.getByte(
          new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET + 5L * Unsafe.ARRAY_BYTE_INDEX_SCALE);
    }

    static void getByteVolatile() {
      UNSAFE.getByteVolatile(new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET - 1);
    }

    static void getByteVolatile_end() {
      UNSAFE.getByteVolatile(
          new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET + 5L * Unsafe.ARRAY_BYTE_INDEX_SCALE);
    }

    static void getChar() {
      UNSAFE.getChar(new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET - 1);
    }

    static void getChar_end() {
      UNSAFE.getChar(
          new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET + 5L * Unsafe.ARRAY_CHAR_INDEX_SCALE);
    }

    static void getCharVolatile() {
      UNSAFE.getCharVolatile(new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET - 1);
    }

    static void getCharVolatile_end() {
      UNSAFE.getCharVolatile(
          new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET + 5L * Unsafe.ARRAY_CHAR_INDEX_SCALE);
    }

    static void getDouble() {
      UNSAFE.getDouble(new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET - 1);
    }

    static void getDouble_end() {
      UNSAFE.getDouble(
          new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET + 5L * Unsafe.ARRAY_DOUBLE_INDEX_SCALE);
    }

    static void getDoubleVolatile() {
      UNSAFE.getDoubleVolatile(new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET - 1);
    }

    static void getDoubleVolatile_end() {
      UNSAFE.getDoubleVolatile(
          new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET + 5L * Unsafe.ARRAY_DOUBLE_INDEX_SCALE);
    }

    static void getFloat() {
      UNSAFE.getFloat(new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET - 1);
    }

    static void getFloat_end() {
      UNSAFE.getFloat(
          new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET + 5L * Unsafe.ARRAY_FLOAT_INDEX_SCALE);
    }

    static void getFloatVolatile() {
      UNSAFE.getFloatVolatile(new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET - 1);
    }

    static void getFloatVolatile_end() {
      UNSAFE.getFloatVolatile(
          new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET + 5L * Unsafe.ARRAY_FLOAT_INDEX_SCALE);
    }

    static void getInt() {
      UNSAFE.getInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET - 1);
    }

    static void getInt_end() {
      UNSAFE.getInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 5L * Unsafe.ARRAY_INT_INDEX_SCALE);
    }

    static void getIntVolatile() {
      UNSAFE.getIntVolatile(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET - 1);
    }

    static void getIntVolatile_end() {
      UNSAFE.getIntVolatile(
          new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 5L * Unsafe.ARRAY_INT_INDEX_SCALE);
    }

    static void getLong() {
      UNSAFE.getLong(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET - 1);
    }

    static void getLong_end() {
      UNSAFE.getLong(
          new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 5L * Unsafe.ARRAY_LONG_INDEX_SCALE);
    }

    static void getLongVolatile() {
      UNSAFE.getLongVolatile(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET - 1);
    }

    static void getLongVolatile_end() {
      UNSAFE.getLongVolatile(
          new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 5L * Unsafe.ARRAY_LONG_INDEX_SCALE);
    }

    static void getObject() {
      UNSAFE.getObject(new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET - 1);
    }

    static void getObject_end() {
      UNSAFE.getObject(
          new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET + 5L * Unsafe.ARRAY_OBJECT_INDEX_SCALE);
    }

    static void getObjectVolatile() {
      UNSAFE.getObjectVolatile(new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET - 1);
    }

    static void getObjectVolatile_end() {
      UNSAFE.getObjectVolatile(
          new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET + 5L * Unsafe.ARRAY_OBJECT_INDEX_SCALE);
    }

    static void getShort() {
      UNSAFE.getShort(new short[5], Unsafe.ARRAY_SHORT_BASE_OFFSET - 1);
    }

    static void getShort_end() {
      UNSAFE.getShort(
          new short[5], Unsafe.ARRAY_SHORT_BASE_OFFSET + 5L * Unsafe.ARRAY_SHORT_INDEX_SCALE);
    }

    static void getShortVolatile() {
      UNSAFE.getShortVolatile(new short[5], Unsafe.ARRAY_SHORT_BASE_OFFSET - 1);
    }

    static void getShortVolatile_end() {
      UNSAFE.getShortVolatile(
          new short[5], Unsafe.ARRAY_SHORT_BASE_OFFSET + 5L * Unsafe.ARRAY_SHORT_INDEX_SCALE);
    }

    static void putBoolean() {
      UNSAFE.putBoolean(new boolean[5], Unsafe.ARRAY_BOOLEAN_BASE_OFFSET - 1, true);
    }

    static void putBoolean_end() {
      UNSAFE.putBoolean(
          new boolean[5],
          Unsafe.ARRAY_BOOLEAN_BASE_OFFSET + 5L * Unsafe.ARRAY_BOOLEAN_INDEX_SCALE,
          true);
    }

    static void putBooleanVolatile() {
      UNSAFE.putBooleanVolatile(new boolean[5], Unsafe.ARRAY_BOOLEAN_BASE_OFFSET - 1, true);
    }

    static void putBooleanVolatile_end() {
      UNSAFE.putBooleanVolatile(
          new boolean[5],
          Unsafe.ARRAY_BOOLEAN_BASE_OFFSET + 5L * Unsafe.ARRAY_BOOLEAN_INDEX_SCALE,
          true);
    }

    static void putByte() {
      UNSAFE.putByte(new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET - 1, (byte) 0);
    }

    static void putByte_end() {
      UNSAFE.putByte(
          new byte[5],
          Unsafe.ARRAY_BYTE_BASE_OFFSET + 5L * Unsafe.ARRAY_BYTE_INDEX_SCALE,
          (byte) 0);
    }

    static void putByteVolatile() {
      UNSAFE.putByteVolatile(new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET - 1, (byte) 0);
    }

    static void putByteVolatile_end() {
      UNSAFE.putByteVolatile(
          new byte[5],
          Unsafe.ARRAY_BYTE_BASE_OFFSET + 5L * Unsafe.ARRAY_BYTE_INDEX_SCALE,
          (byte) 0);
    }

    static void putChar() {
      UNSAFE.putChar(new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET - 1, 'a');
    }

    static void putChar_end() {
      UNSAFE.putChar(
          new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET + 5L * Unsafe.ARRAY_CHAR_INDEX_SCALE, 'a');
    }

    static void putCharVolatile() {
      UNSAFE.putCharVolatile(new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET - 1, 'a');
    }

    static void putCharVolatile_end() {
      UNSAFE.putCharVolatile(
          new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET + 5L * Unsafe.ARRAY_CHAR_INDEX_SCALE, 'a');
    }

    static void putDouble() {
      UNSAFE.putDouble(new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET - 1, 0);
    }

    static void putDouble_end() {
      UNSAFE.putDouble(
          new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET + 5L * Unsafe.ARRAY_DOUBLE_INDEX_SCALE, 0);
    }

    static void putDoubleVolatile() {
      UNSAFE.putDoubleVolatile(new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET - 1, 0);
    }

    static void putDoubleVolatile_end() {
      UNSAFE.putDoubleVolatile(
          new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET + 5L * Unsafe.ARRAY_DOUBLE_INDEX_SCALE, 0);
    }

    static void putFloat() {
      UNSAFE.putFloat(new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET - 1, 0);
    }

    static void putFloat_end() {
      UNSAFE.putFloat(
          new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET + 5L * Unsafe.ARRAY_FLOAT_INDEX_SCALE, 0);
    }

    static void putFloatVolatile() {
      UNSAFE.putFloatVolatile(new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET - 1, 0);
    }

    static void putFloatVolatile_end() {
      UNSAFE.putFloatVolatile(
          new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET + 5L * Unsafe.ARRAY_FLOAT_INDEX_SCALE, 0);
    }

    static void putInt() {
      UNSAFE.putInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET - 1, 0);
    }

    static void putInt_end() {
      UNSAFE.putInt(
          new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 5L * Unsafe.ARRAY_INT_INDEX_SCALE, 0);
    }

    static void putIntVolatile() {
      UNSAFE.putIntVolatile(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET - 1, 0);
    }

    static void putIntVolatile_end() {
      UNSAFE.putIntVolatile(
          new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 5L * Unsafe.ARRAY_INT_INDEX_SCALE, 0);
    }

    static void putLong() {
      UNSAFE.putLong(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET - 1, 0);
    }

    static void putLong_end() {
      UNSAFE.putLong(
          new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 5L * Unsafe.ARRAY_LONG_INDEX_SCALE, 0);
    }

    static void putLongVolatile() {
      UNSAFE.putLongVolatile(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET - 1, 0);
    }

    static void putLongVolatile_end() {
      UNSAFE.putLongVolatile(
          new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 5L * Unsafe.ARRAY_LONG_INDEX_SCALE, 0);
    }

    static void putObject() {
      UNSAFE.putObject(new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET - 1, 0);
    }

    static void putObject_end() {
      UNSAFE.putObject(
          new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET + 5L * Unsafe.ARRAY_OBJECT_INDEX_SCALE, 0);
    }

    static void putObjectVolatile() {
      UNSAFE.putObjectVolatile(new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET - 1, 0);
    }

    static void putObjectVolatile_end() {
      UNSAFE.putObjectVolatile(
          new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET + 5L * Unsafe.ARRAY_OBJECT_INDEX_SCALE, 0);
    }

    static void putOrderedInt() {
      UNSAFE.putOrderedInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET - 1, 0);
    }

    static void putOrderedInt_end() {
      UNSAFE.putOrderedInt(
          new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 5L * Unsafe.ARRAY_INT_INDEX_SCALE, 0);
    }

    static void putOrderedLong() {
      UNSAFE.putOrderedLong(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET - 1, 0);
    }

    static void putOrderedLong_end() {
      UNSAFE.putOrderedLong(
          new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 5L * Unsafe.ARRAY_LONG_INDEX_SCALE, 0);
    }

    static void putOrderedObject() {
      UNSAFE.putOrderedObject(new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET - 1, 0);
    }

    static void putOrderedObject_end() {
      UNSAFE.putOrderedObject(
          new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET + 5L * Unsafe.ARRAY_OBJECT_INDEX_SCALE, 0);
    }

    static void putShort() {
      UNSAFE.putShort(new short[5], Unsafe.ARRAY_SHORT_BASE_OFFSET - 1, (short) 0);
    }

    static void putShort_end() {
      UNSAFE.putShort(
          new short[5],
          Unsafe.ARRAY_SHORT_BASE_OFFSET + 5L * Unsafe.ARRAY_SHORT_INDEX_SCALE,
          (short) 0);
    }

    static void putShortVolatile() {
      UNSAFE.putShortVolatile(new short[5], Unsafe.ARRAY_SHORT_BASE_OFFSET - 1, (short) 0);
    }

    static void putShortVolatile_end() {
      UNSAFE.putShortVolatile(
          new short[5],
          Unsafe.ARRAY_SHORT_BASE_OFFSET + 5L * Unsafe.ARRAY_SHORT_INDEX_SCALE,
          (short) 0);
    }

    static void copyMemory() {
      UNSAFE.copyMemory(
          new byte[5],
          Unsafe.ARRAY_BYTE_BASE_OFFSET - 1,
          new byte[5],
          Unsafe.ARRAY_BYTE_BASE_OFFSET,
          2);
    }

    static void copyMemory_end() {
      UNSAFE.copyMemory(
          new byte[5],
          Unsafe.ARRAY_BYTE_BASE_OFFSET + 4L * Unsafe.ARRAY_BYTE_INDEX_SCALE,
          new byte[5],
          Unsafe.ARRAY_BYTE_BASE_OFFSET,
          2);
    }

    static void copyMemory_dest() {
      UNSAFE.copyMemory(
          new byte[5],
          Unsafe.ARRAY_BYTE_BASE_OFFSET,
          new byte[5],
          Unsafe.ARRAY_BYTE_BASE_OFFSET - 1,
          2);
    }

    static void copyMemory_dest_end() {
      UNSAFE.copyMemory(
          new byte[5],
          Unsafe.ARRAY_BYTE_BASE_OFFSET,
          new byte[5],
          Unsafe.ARRAY_BYTE_BASE_OFFSET + 4L * Unsafe.ARRAY_BYTE_INDEX_SCALE,
          2);
    }

    static void setMemory() {
      UNSAFE.setMemory(new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET - 1, 2, (byte) 0);
    }

    static void setMemory_end() {
      UNSAFE.setMemory(
          new byte[5],
          Unsafe.ARRAY_BYTE_BASE_OFFSET + 4L * Unsafe.ARRAY_BYTE_INDEX_SCALE,
          2,
          (byte) 0);
    }

    // The following covers some additional special cases of invalid memory access
    static void byteAccessOnObjectArray() {
      UNSAFE.getByte(new String[10], Unsafe.ARRAY_OBJECT_BASE_OFFSET);
    }

    static void objectAccessOnPrimitiveArray() {
      UNSAFE.getObject(new byte[100], Unsafe.ARRAY_BYTE_BASE_OFFSET);
    }

    static void unalignedObjectAccess() {
      assert Unsafe.ARRAY_OBJECT_INDEX_SCALE != 1;
      UNSAFE.getObject(new String[2], Unsafe.ARRAY_OBJECT_BASE_OFFSET + 1);
    }
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
    Method[] testMethods = TestMethods.class.getDeclaredMethods();
    // Since all of these methods are expected to cause a sanitizer exception, pick a random one and
    // run it
    // TODO: Is this a proper way to implement this?
    Method testMethod = testMethods[data.consumeInt(0, testMethods.length - 1)];

    testMethod.invoke(null);

    throw new AssertionError("No sanitizer exception was thrown for " + testMethod);
  }
}
