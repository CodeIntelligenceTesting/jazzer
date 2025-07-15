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

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.lang.reflect.Field;
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

  /*
   * These test methods all perform invalid memory access with Unsafe.
   * IMPORTANT: When adding new methods, the list of method names in `BUILD.bazel` has to be adjusted as well.
   */

  @FuzzTest
  public void compareAndSwapInt(Boolean ignored) {
    UNSAFE.compareAndSwapInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET - 1, 0, 1);
  }

  @FuzzTest
  public void compareAndSwapInt_end(Boolean ignored) {
    UNSAFE.compareAndSwapInt(
        new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 5L * Unsafe.ARRAY_INT_INDEX_SCALE, 0, 1);
  }

  @FuzzTest
  public void compareAndSwapLong(Boolean ignored) {
    UNSAFE.compareAndSwapLong(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET - 1, 0, 1);
  }

  @FuzzTest
  public void compareAndSwapLong_end(Boolean ignored) {
    UNSAFE.compareAndSwapLong(
        new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 5L * Unsafe.ARRAY_LONG_INDEX_SCALE, 0, 1);
  }

  @FuzzTest
  public void compareAndSwapObject(Boolean ignored) {
    UNSAFE.compareAndSwapObject(new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET - 1, "a", "b");
  }

  @FuzzTest
  public void compareAndSwapObject_end(Boolean ignored) {
    UNSAFE.compareAndSwapObject(
        new Object[5],
        Unsafe.ARRAY_OBJECT_BASE_OFFSET + 5L * Unsafe.ARRAY_OBJECT_INDEX_SCALE,
        "a",
        "b");
  }

  @FuzzTest
  public void getAndAddInt(Boolean ignored) {
    UNSAFE.getAndAddInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET - 1, 1);
  }

  @FuzzTest
  public void getAndAddInt_end(Boolean ignored) {
    UNSAFE.getAndAddInt(
        new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 5L * Unsafe.ARRAY_INT_INDEX_SCALE, 1);
  }

  @FuzzTest
  public void getAndAddLong(Boolean ignored) {
    UNSAFE.getAndAddLong(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET - 1, 1);
  }

  @FuzzTest
  public void getAndAddLong_end(Boolean ignored) {
    UNSAFE.getAndAddLong(
        new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 5L * Unsafe.ARRAY_LONG_INDEX_SCALE, 1);
  }

  @FuzzTest
  public void getAndSetInt(Boolean ignored) {
    UNSAFE.getAndSetInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET - 1, 1);
  }

  @FuzzTest
  public void getAndSetInt_end(Boolean ignored) {
    UNSAFE.getAndSetInt(
        new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 5L * Unsafe.ARRAY_INT_INDEX_SCALE, 1);
  }

  @FuzzTest
  public void getAndSetLong(Boolean ignored) {
    UNSAFE.getAndSetLong(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET - 1, 1);
  }

  @FuzzTest
  public void getAndSetLong_end(Boolean ignored) {
    UNSAFE.getAndSetLong(
        new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 5L * Unsafe.ARRAY_LONG_INDEX_SCALE, 1);
  }

  @FuzzTest
  public void getAndSetObject(Boolean ignored) {
    UNSAFE.getAndSetObject(new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET - 1, "a");
  }

  @FuzzTest
  public void getAndSetObject_end(Boolean ignored) {
    UNSAFE.getAndSetObject(
        new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET + 5L * Unsafe.ARRAY_OBJECT_INDEX_SCALE, "a");
  }

  @FuzzTest
  public void getBoolean(Boolean ignored) {
    UNSAFE.getBoolean(new boolean[5], Unsafe.ARRAY_BOOLEAN_BASE_OFFSET - 1);
  }

  @FuzzTest
  public void getBoolean_end(Boolean ignored) {
    UNSAFE.getBoolean(
        new boolean[5], Unsafe.ARRAY_BOOLEAN_BASE_OFFSET + 5L * Unsafe.ARRAY_BOOLEAN_INDEX_SCALE);
  }

  @FuzzTest
  public void getBooleanVolatile(Boolean ignored) {
    UNSAFE.getBooleanVolatile(new boolean[5], Unsafe.ARRAY_BOOLEAN_BASE_OFFSET - 1);
  }

  @FuzzTest
  public void getBooleanVolatile_end(Boolean ignored) {
    UNSAFE.getBooleanVolatile(
        new boolean[5], Unsafe.ARRAY_BOOLEAN_BASE_OFFSET + 5L * Unsafe.ARRAY_BOOLEAN_INDEX_SCALE);
  }

  @FuzzTest
  public void getByte(Boolean ignored) {
    UNSAFE.getByte(new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET - 1);
  }

  @FuzzTest
  public void getByte_end(Boolean ignored) {
    UNSAFE.getByte(new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET + 5L * Unsafe.ARRAY_BYTE_INDEX_SCALE);
  }

  @FuzzTest
  public void getByteVolatile(Boolean ignored) {
    UNSAFE.getByteVolatile(new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET - 1);
  }

  @FuzzTest
  public void getByteVolatile_end(Boolean ignored) {
    UNSAFE.getByteVolatile(
        new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET + 5L * Unsafe.ARRAY_BYTE_INDEX_SCALE);
  }

  @FuzzTest
  public void getChar(Boolean ignored) {
    UNSAFE.getChar(new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET - 1);
  }

  @FuzzTest
  public void getChar_end(Boolean ignored) {
    UNSAFE.getChar(new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET + 5L * Unsafe.ARRAY_CHAR_INDEX_SCALE);
  }

  @FuzzTest
  public void getCharVolatile(Boolean ignored) {
    UNSAFE.getCharVolatile(new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET - 1);
  }

  @FuzzTest
  public void getCharVolatile_end(Boolean ignored) {
    UNSAFE.getCharVolatile(
        new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET + 5L * Unsafe.ARRAY_CHAR_INDEX_SCALE);
  }

  @FuzzTest
  public void getDouble(Boolean ignored) {
    UNSAFE.getDouble(new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET - 1);
  }

  @FuzzTest
  public void getDouble_end(Boolean ignored) {
    UNSAFE.getDouble(
        new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET + 5L * Unsafe.ARRAY_DOUBLE_INDEX_SCALE);
  }

  @FuzzTest
  public void getDoubleVolatile(Boolean ignored) {
    UNSAFE.getDoubleVolatile(new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET - 1);
  }

  @FuzzTest
  public void getDoubleVolatile_end(Boolean ignored) {
    UNSAFE.getDoubleVolatile(
        new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET + 5L * Unsafe.ARRAY_DOUBLE_INDEX_SCALE);
  }

  @FuzzTest
  public void getFloat(Boolean ignored) {
    UNSAFE.getFloat(new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET - 1);
  }

  @FuzzTest
  public void getFloat_end(Boolean ignored) {
    UNSAFE.getFloat(
        new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET + 5L * Unsafe.ARRAY_FLOAT_INDEX_SCALE);
  }

  @FuzzTest
  public void getFloatVolatile(Boolean ignored) {
    UNSAFE.getFloatVolatile(new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET - 1);
  }

  @FuzzTest
  public void getFloatVolatile_end(Boolean ignored) {
    UNSAFE.getFloatVolatile(
        new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET + 5L * Unsafe.ARRAY_FLOAT_INDEX_SCALE);
  }

  @FuzzTest
  public void getInt(Boolean ignored) {
    UNSAFE.getInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET - 1);
  }

  @FuzzTest
  public void getInt_end(Boolean ignored) {
    UNSAFE.getInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 5L * Unsafe.ARRAY_INT_INDEX_SCALE);
  }

  @FuzzTest
  public void getIntVolatile(Boolean ignored) {
    UNSAFE.getIntVolatile(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET - 1);
  }

  @FuzzTest
  public void getIntVolatile_end(Boolean ignored) {
    UNSAFE.getIntVolatile(
        new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 5L * Unsafe.ARRAY_INT_INDEX_SCALE);
  }

  @FuzzTest
  public void getLong(Boolean ignored) {
    UNSAFE.getLong(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET - 1);
  }

  @FuzzTest
  public void getLong_end(Boolean ignored) {
    UNSAFE.getLong(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 5L * Unsafe.ARRAY_LONG_INDEX_SCALE);
  }

  @FuzzTest
  public void getLongVolatile(Boolean ignored) {
    UNSAFE.getLongVolatile(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET - 1);
  }

  @FuzzTest
  public void getLongVolatile_end(Boolean ignored) {
    UNSAFE.getLongVolatile(
        new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 5L * Unsafe.ARRAY_LONG_INDEX_SCALE);
  }

  @FuzzTest
  public void getObject(Boolean ignored) {
    UNSAFE.getObject(new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET - 1);
  }

  @FuzzTest
  public void getObject_end(Boolean ignored) {
    UNSAFE.getObject(
        new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET + 5L * Unsafe.ARRAY_OBJECT_INDEX_SCALE);
  }

  @FuzzTest
  public void getObjectVolatile(Boolean ignored) {
    UNSAFE.getObjectVolatile(new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET - 1);
  }

  @FuzzTest
  public void getObjectVolatile_end(Boolean ignored) {
    UNSAFE.getObjectVolatile(
        new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET + 5L * Unsafe.ARRAY_OBJECT_INDEX_SCALE);
  }

  @FuzzTest
  public void getShort(Boolean ignored) {
    UNSAFE.getShort(new short[5], Unsafe.ARRAY_SHORT_BASE_OFFSET - 1);
  }

  @FuzzTest
  public void getShort_end(Boolean ignored) {
    UNSAFE.getShort(
        new short[5], Unsafe.ARRAY_SHORT_BASE_OFFSET + 5L * Unsafe.ARRAY_SHORT_INDEX_SCALE);
  }

  @FuzzTest
  public void getShortVolatile(Boolean ignored) {
    UNSAFE.getShortVolatile(new short[5], Unsafe.ARRAY_SHORT_BASE_OFFSET - 1);
  }

  @FuzzTest
  public void getShortVolatile_end(Boolean ignored) {
    UNSAFE.getShortVolatile(
        new short[5], Unsafe.ARRAY_SHORT_BASE_OFFSET + 5L * Unsafe.ARRAY_SHORT_INDEX_SCALE);
  }

  @FuzzTest
  public void putBoolean(Boolean ignored) {
    UNSAFE.putBoolean(new boolean[5], Unsafe.ARRAY_BOOLEAN_BASE_OFFSET - 1, true);
  }

  @FuzzTest
  public void putBoolean_end(Boolean ignored) {
    UNSAFE.putBoolean(
        new boolean[5],
        Unsafe.ARRAY_BOOLEAN_BASE_OFFSET + 5L * Unsafe.ARRAY_BOOLEAN_INDEX_SCALE,
        true);
  }

  @FuzzTest
  public void putBooleanVolatile(Boolean ignored) {
    UNSAFE.putBooleanVolatile(new boolean[5], Unsafe.ARRAY_BOOLEAN_BASE_OFFSET - 1, true);
  }

  @FuzzTest
  public void putBooleanVolatile_end(Boolean ignored) {
    UNSAFE.putBooleanVolatile(
        new boolean[5],
        Unsafe.ARRAY_BOOLEAN_BASE_OFFSET + 5L * Unsafe.ARRAY_BOOLEAN_INDEX_SCALE,
        true);
  }

  @FuzzTest
  public void putByte(Boolean ignored) {
    UNSAFE.putByte(new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET - 1, (byte) 0);
  }

  @FuzzTest
  public void putByte_end(Boolean ignored) {
    UNSAFE.putByte(
        new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET + 5L * Unsafe.ARRAY_BYTE_INDEX_SCALE, (byte) 0);
  }

  @FuzzTest
  public void putByteVolatile(Boolean ignored) {
    UNSAFE.putByteVolatile(new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET - 1, (byte) 0);
  }

  @FuzzTest
  public void putByteVolatile_end(Boolean ignored) {
    UNSAFE.putByteVolatile(
        new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET + 5L * Unsafe.ARRAY_BYTE_INDEX_SCALE, (byte) 0);
  }

  @FuzzTest
  public void putChar(Boolean ignored) {
    UNSAFE.putChar(new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET - 1, 'a');
  }

  @FuzzTest
  public void putChar_end(Boolean ignored) {
    UNSAFE.putChar(
        new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET + 5L * Unsafe.ARRAY_CHAR_INDEX_SCALE, 'a');
  }

  @FuzzTest
  public void putCharVolatile(Boolean ignored) {
    UNSAFE.putCharVolatile(new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET - 1, 'a');
  }

  @FuzzTest
  public void putCharVolatile_end(Boolean ignored) {
    UNSAFE.putCharVolatile(
        new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET + 5L * Unsafe.ARRAY_CHAR_INDEX_SCALE, 'a');
  }

  @FuzzTest
  public void putDouble(Boolean ignored) {
    UNSAFE.putDouble(new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET - 1, 0);
  }

  @FuzzTest
  public void putDouble_end(Boolean ignored) {
    UNSAFE.putDouble(
        new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET + 5L * Unsafe.ARRAY_DOUBLE_INDEX_SCALE, 0);
  }

  @FuzzTest
  public void putDoubleVolatile(Boolean ignored) {
    UNSAFE.putDoubleVolatile(new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET - 1, 0);
  }

  @FuzzTest
  public void putDoubleVolatile_end(Boolean ignored) {
    UNSAFE.putDoubleVolatile(
        new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET + 5L * Unsafe.ARRAY_DOUBLE_INDEX_SCALE, 0);
  }

  @FuzzTest
  public void putFloat(Boolean ignored) {
    UNSAFE.putFloat(new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET - 1, 0);
  }

  @FuzzTest
  public void putFloat_end(Boolean ignored) {
    UNSAFE.putFloat(
        new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET + 5L * Unsafe.ARRAY_FLOAT_INDEX_SCALE, 0);
  }

  @FuzzTest
  public void putFloatVolatile(Boolean ignored) {
    UNSAFE.putFloatVolatile(new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET - 1, 0);
  }

  @FuzzTest
  public void putFloatVolatile_end(Boolean ignored) {
    UNSAFE.putFloatVolatile(
        new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET + 5L * Unsafe.ARRAY_FLOAT_INDEX_SCALE, 0);
  }

  @FuzzTest
  public void putInt(Boolean ignored) {
    UNSAFE.putInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET - 1, 0);
  }

  @FuzzTest
  public void putInt_end(Boolean ignored) {
    UNSAFE.putInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 5L * Unsafe.ARRAY_INT_INDEX_SCALE, 0);
  }

  @FuzzTest
  public void putIntVolatile(Boolean ignored) {
    UNSAFE.putIntVolatile(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET - 1, 0);
  }

  @FuzzTest
  public void putIntVolatile_end(Boolean ignored) {
    UNSAFE.putIntVolatile(
        new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 5L * Unsafe.ARRAY_INT_INDEX_SCALE, 0);
  }

  @FuzzTest
  public void putLong(Boolean ignored) {
    UNSAFE.putLong(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET - 1, 0);
  }

  @FuzzTest
  public void putLong_end(Boolean ignored) {
    UNSAFE.putLong(
        new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 5L * Unsafe.ARRAY_LONG_INDEX_SCALE, 0);
  }

  @FuzzTest
  public void putLongVolatile(Boolean ignored) {
    UNSAFE.putLongVolatile(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET - 1, 0);
  }

  @FuzzTest
  public void putLongVolatile_end(Boolean ignored) {
    UNSAFE.putLongVolatile(
        new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 5L * Unsafe.ARRAY_LONG_INDEX_SCALE, 0);
  }

  @FuzzTest
  public void putObject(Boolean ignored) {
    UNSAFE.putObject(new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET - 1, 0);
  }

  @FuzzTest
  public void putObject_end(Boolean ignored) {
    UNSAFE.putObject(
        new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET + 5L * Unsafe.ARRAY_OBJECT_INDEX_SCALE, 0);
  }

  @FuzzTest
  public void putObjectVolatile(Boolean ignored) {
    UNSAFE.putObjectVolatile(new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET - 1, 0);
  }

  @FuzzTest
  public void putObjectVolatile_end(Boolean ignored) {
    UNSAFE.putObjectVolatile(
        new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET + 5L * Unsafe.ARRAY_OBJECT_INDEX_SCALE, 0);
  }

  @FuzzTest
  public void putOrderedInt(Boolean ignored) {
    UNSAFE.putOrderedInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET - 1, 0);
  }

  @FuzzTest
  public void putOrderedInt_end(Boolean ignored) {
    UNSAFE.putOrderedInt(
        new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 5L * Unsafe.ARRAY_INT_INDEX_SCALE, 0);
  }

  @FuzzTest
  public void putOrderedLong(Boolean ignored) {
    UNSAFE.putOrderedLong(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET - 1, 0);
  }

  @FuzzTest
  public void putOrderedLong_end(Boolean ignored) {
    UNSAFE.putOrderedLong(
        new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 5L * Unsafe.ARRAY_LONG_INDEX_SCALE, 0);
  }

  @FuzzTest
  public void putOrderedObject(Boolean ignored) {
    UNSAFE.putOrderedObject(new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET - 1, 0);
  }

  @FuzzTest
  public void putOrderedObject_end(Boolean ignored) {
    UNSAFE.putOrderedObject(
        new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET + 5L * Unsafe.ARRAY_OBJECT_INDEX_SCALE, 0);
  }

  @FuzzTest
  public void putShort(Boolean ignored) {
    UNSAFE.putShort(new short[5], Unsafe.ARRAY_SHORT_BASE_OFFSET - 1, (short) 0);
  }

  @FuzzTest
  public void putShort_end(Boolean ignored) {
    UNSAFE.putShort(
        new short[5],
        Unsafe.ARRAY_SHORT_BASE_OFFSET + 5L * Unsafe.ARRAY_SHORT_INDEX_SCALE,
        (short) 0);
  }

  @FuzzTest
  public void putShortVolatile(Boolean ignored) {
    UNSAFE.putShortVolatile(new short[5], Unsafe.ARRAY_SHORT_BASE_OFFSET - 1, (short) 0);
  }

  @FuzzTest
  public void putShortVolatile_end(Boolean ignored) {
    UNSAFE.putShortVolatile(
        new short[5],
        Unsafe.ARRAY_SHORT_BASE_OFFSET + 5L * Unsafe.ARRAY_SHORT_INDEX_SCALE,
        (short) 0);
  }

  @FuzzTest
  public void copyMemory(Boolean ignored) {
    UNSAFE.copyMemory(
        new byte[5],
        Unsafe.ARRAY_BYTE_BASE_OFFSET - 1,
        new byte[5],
        Unsafe.ARRAY_BYTE_BASE_OFFSET,
        2);
  }

  @FuzzTest
  public void copyMemory_end(Boolean ignored) {
    UNSAFE.copyMemory(
        new byte[5],
        Unsafe.ARRAY_BYTE_BASE_OFFSET + 4L * Unsafe.ARRAY_BYTE_INDEX_SCALE,
        new byte[5],
        Unsafe.ARRAY_BYTE_BASE_OFFSET,
        2);
  }

  @FuzzTest
  public void copyMemory_dest(Boolean ignored) {
    UNSAFE.copyMemory(
        new byte[5],
        Unsafe.ARRAY_BYTE_BASE_OFFSET,
        new byte[5],
        Unsafe.ARRAY_BYTE_BASE_OFFSET - 1,
        2);
  }

  @FuzzTest
  public void copyMemory_dest_end(Boolean ignored) {
    UNSAFE.copyMemory(
        new byte[5],
        Unsafe.ARRAY_BYTE_BASE_OFFSET,
        new byte[5],
        Unsafe.ARRAY_BYTE_BASE_OFFSET + 4L * Unsafe.ARRAY_BYTE_INDEX_SCALE,
        2);
  }

  @FuzzTest
  public void setMemory(Boolean ignored) {
    UNSAFE.setMemory(new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET - 1, 2, (byte) 0);
  }

  @FuzzTest
  public void setMemory_end(Boolean ignored) {
    UNSAFE.setMemory(
        new byte[5],
        Unsafe.ARRAY_BYTE_BASE_OFFSET + 4L * Unsafe.ARRAY_BYTE_INDEX_SCALE,
        2,
        (byte) 0);
  }

  // The following covers some additional special cases of invalid memory access
  @FuzzTest
  public void byteAccessOnObjectArray(Boolean ignored) {
    UNSAFE.getByte(new String[10], Unsafe.ARRAY_OBJECT_BASE_OFFSET);
  }

  @FuzzTest
  public void objectAccessOnPrimitiveArray(Boolean ignored) {
    UNSAFE.getObject(new byte[100], Unsafe.ARRAY_BYTE_BASE_OFFSET);
  }

  @FuzzTest
  public void unalignedObjectAccess(Boolean ignored) {
    assert Unsafe.ARRAY_OBJECT_INDEX_SCALE != 1;
    UNSAFE.getObject(new String[2], Unsafe.ARRAY_OBJECT_BASE_OFFSET + 1);
  }
}
