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
import sun.misc.Unsafe;

/** Verifies that valid {@link Unsafe} usage does not cause a spurious sanitizer exception. */
public class UnsafeArrayValid {
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

  public static void fuzzerTestOneInput(FuzzedDataProvider ignored) throws Exception {
    UNSAFE.compareAndSwapInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET, 0, 1);
    UNSAFE.compareAndSwapInt(
        new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 4L * Unsafe.ARRAY_INT_INDEX_SCALE, 0, 1);

    UNSAFE.compareAndSwapLong(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET, 0, 1);
    UNSAFE.compareAndSwapLong(
        new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 4L * Unsafe.ARRAY_LONG_INDEX_SCALE, 0, 1);

    UNSAFE.compareAndSwapObject(new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET, "a", "b");
    UNSAFE.compareAndSwapObject(
        new Object[5],
        Unsafe.ARRAY_OBJECT_BASE_OFFSET + 4L * Unsafe.ARRAY_OBJECT_INDEX_SCALE,
        "a",
        "b");

    UNSAFE.getAndAddInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET, 1);
    UNSAFE.getAndAddInt(
        new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 4L * Unsafe.ARRAY_INT_INDEX_SCALE, 1);

    UNSAFE.getAndAddLong(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET, 1);
    UNSAFE.getAndAddLong(
        new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 4L * Unsafe.ARRAY_LONG_INDEX_SCALE, 1);

    UNSAFE.getAndSetInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET, 1);
    UNSAFE.getAndSetInt(
        new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 4L * Unsafe.ARRAY_INT_INDEX_SCALE, 1);

    UNSAFE.getAndSetLong(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET, 1);
    UNSAFE.getAndSetLong(
        new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 4L * Unsafe.ARRAY_LONG_INDEX_SCALE, 1);

    UNSAFE.getAndSetObject(new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET, "a");
    UNSAFE.getAndSetObject(
        new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET + 4L * Unsafe.ARRAY_OBJECT_INDEX_SCALE, "a");

    UNSAFE.getBoolean(new boolean[5], Unsafe.ARRAY_BOOLEAN_BASE_OFFSET);
    UNSAFE.getBoolean(
        new boolean[5], Unsafe.ARRAY_BOOLEAN_BASE_OFFSET + 4L * Unsafe.ARRAY_BOOLEAN_INDEX_SCALE);

    UNSAFE.getBooleanVolatile(new boolean[5], Unsafe.ARRAY_BOOLEAN_BASE_OFFSET);
    UNSAFE.getBooleanVolatile(
        new boolean[5], Unsafe.ARRAY_BOOLEAN_BASE_OFFSET + 4L * Unsafe.ARRAY_BOOLEAN_INDEX_SCALE);

    UNSAFE.getByte(new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET);
    UNSAFE.getByte(new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET + 4L * Unsafe.ARRAY_BYTE_INDEX_SCALE);

    UNSAFE.getByteVolatile(new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET);
    UNSAFE.getByteVolatile(
        new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET + 4L * Unsafe.ARRAY_BYTE_INDEX_SCALE);

    UNSAFE.getChar(new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET);
    UNSAFE.getChar(new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET + 4L * Unsafe.ARRAY_CHAR_INDEX_SCALE);

    UNSAFE.getCharVolatile(new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET);
    UNSAFE.getCharVolatile(
        new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET + 4L * Unsafe.ARRAY_CHAR_INDEX_SCALE);

    UNSAFE.getDouble(new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET);
    UNSAFE.getDouble(
        new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET + 4L * Unsafe.ARRAY_DOUBLE_INDEX_SCALE);

    UNSAFE.getDoubleVolatile(new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET);
    UNSAFE.getDoubleVolatile(
        new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET + 4L * Unsafe.ARRAY_DOUBLE_INDEX_SCALE);

    UNSAFE.getFloat(new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET);
    UNSAFE.getFloat(
        new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET + 4L * Unsafe.ARRAY_FLOAT_INDEX_SCALE);

    UNSAFE.getFloatVolatile(new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET);
    UNSAFE.getFloatVolatile(
        new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET + 4L * Unsafe.ARRAY_FLOAT_INDEX_SCALE);

    UNSAFE.getInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET);
    UNSAFE.getInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 4L * Unsafe.ARRAY_INT_INDEX_SCALE);

    UNSAFE.getIntVolatile(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET);
    UNSAFE.getIntVolatile(
        new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 4L * Unsafe.ARRAY_INT_INDEX_SCALE);

    UNSAFE.getLong(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET);
    UNSAFE.getLong(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 4L * Unsafe.ARRAY_LONG_INDEX_SCALE);

    UNSAFE.getLongVolatile(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET);
    UNSAFE.getLongVolatile(
        new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 4L * Unsafe.ARRAY_LONG_INDEX_SCALE);

    UNSAFE.getObject(new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET);
    UNSAFE.getObject(
        new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET + 4L * Unsafe.ARRAY_OBJECT_INDEX_SCALE);

    UNSAFE.getObjectVolatile(new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET);
    UNSAFE.getObjectVolatile(
        new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET + 4L * Unsafe.ARRAY_OBJECT_INDEX_SCALE);

    UNSAFE.getShort(new short[5], Unsafe.ARRAY_SHORT_BASE_OFFSET);
    UNSAFE.getShort(
        new short[5], Unsafe.ARRAY_SHORT_BASE_OFFSET + 4L * Unsafe.ARRAY_SHORT_INDEX_SCALE);

    UNSAFE.getShortVolatile(new short[5], Unsafe.ARRAY_SHORT_BASE_OFFSET);
    UNSAFE.getShortVolatile(
        new short[5], Unsafe.ARRAY_SHORT_BASE_OFFSET + 4L * Unsafe.ARRAY_SHORT_INDEX_SCALE);

    UNSAFE.putBoolean(new boolean[5], Unsafe.ARRAY_BOOLEAN_BASE_OFFSET, true);
    UNSAFE.putBoolean(
        new boolean[5],
        Unsafe.ARRAY_BOOLEAN_BASE_OFFSET + 4L * Unsafe.ARRAY_BOOLEAN_INDEX_SCALE,
        true);

    UNSAFE.putBooleanVolatile(new boolean[5], Unsafe.ARRAY_BOOLEAN_BASE_OFFSET, true);
    UNSAFE.putBooleanVolatile(
        new boolean[5],
        Unsafe.ARRAY_BOOLEAN_BASE_OFFSET + 4L * Unsafe.ARRAY_BOOLEAN_INDEX_SCALE,
        true);

    UNSAFE.putByte(new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET, (byte) 0);
    UNSAFE.putByte(
        new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET + 4L * Unsafe.ARRAY_BYTE_INDEX_SCALE, (byte) 0);

    UNSAFE.putByteVolatile(new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET, (byte) 0);
    UNSAFE.putByteVolatile(
        new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET + 4L * Unsafe.ARRAY_BYTE_INDEX_SCALE, (byte) 0);

    UNSAFE.putChar(new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET, 'a');
    UNSAFE.putChar(
        new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET + 4L * Unsafe.ARRAY_CHAR_INDEX_SCALE, 'a');

    UNSAFE.putCharVolatile(new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET, 'a');
    UNSAFE.putCharVolatile(
        new char[5], Unsafe.ARRAY_CHAR_BASE_OFFSET + 4L * Unsafe.ARRAY_CHAR_INDEX_SCALE, 'a');

    UNSAFE.putDouble(new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET, 0);
    UNSAFE.putDouble(
        new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET + 4L * Unsafe.ARRAY_DOUBLE_INDEX_SCALE, 0);

    UNSAFE.putDoubleVolatile(new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET, 0);
    UNSAFE.putDoubleVolatile(
        new double[5], Unsafe.ARRAY_DOUBLE_BASE_OFFSET + 4L * Unsafe.ARRAY_DOUBLE_INDEX_SCALE, 0);

    UNSAFE.putFloat(new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET, 0);
    UNSAFE.putFloat(
        new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET + 4L * Unsafe.ARRAY_FLOAT_INDEX_SCALE, 0);

    UNSAFE.putFloatVolatile(new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET, 0);
    UNSAFE.putFloatVolatile(
        new float[5], Unsafe.ARRAY_FLOAT_BASE_OFFSET + 4L * Unsafe.ARRAY_FLOAT_INDEX_SCALE, 0);

    UNSAFE.putInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET, 0);
    UNSAFE.putInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 4L * Unsafe.ARRAY_INT_INDEX_SCALE, 0);

    UNSAFE.putIntVolatile(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET, 0);
    UNSAFE.putIntVolatile(
        new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 4L * Unsafe.ARRAY_INT_INDEX_SCALE, 0);

    UNSAFE.putLong(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET, 0);
    UNSAFE.putLong(
        new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 4L * Unsafe.ARRAY_LONG_INDEX_SCALE, 0);

    UNSAFE.putLongVolatile(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET, 0);
    UNSAFE.putLongVolatile(
        new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 4L * Unsafe.ARRAY_LONG_INDEX_SCALE, 0);

    UNSAFE.putObject(new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET, 0);
    UNSAFE.putObject(
        new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET + 4L * Unsafe.ARRAY_OBJECT_INDEX_SCALE, 0);

    UNSAFE.putObjectVolatile(new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET, 0);
    UNSAFE.putObjectVolatile(
        new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET + 4L * Unsafe.ARRAY_OBJECT_INDEX_SCALE, 0);

    UNSAFE.putOrderedInt(new int[5], Unsafe.ARRAY_INT_BASE_OFFSET, 0);
    UNSAFE.putOrderedInt(
        new int[5], Unsafe.ARRAY_INT_BASE_OFFSET + 4L * Unsafe.ARRAY_INT_INDEX_SCALE, 0);

    UNSAFE.putOrderedLong(new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET, 0);
    UNSAFE.putOrderedLong(
        new long[5], Unsafe.ARRAY_LONG_BASE_OFFSET + 4L * Unsafe.ARRAY_LONG_INDEX_SCALE, 0);

    UNSAFE.putOrderedObject(new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET, 0);
    UNSAFE.putOrderedObject(
        new Object[5], Unsafe.ARRAY_OBJECT_BASE_OFFSET + 4L * Unsafe.ARRAY_OBJECT_INDEX_SCALE, 0);

    UNSAFE.putShort(new short[5], Unsafe.ARRAY_SHORT_BASE_OFFSET, (short) 0);
    UNSAFE.putShort(
        new short[5],
        Unsafe.ARRAY_SHORT_BASE_OFFSET + 4L * Unsafe.ARRAY_SHORT_INDEX_SCALE,
        (short) 0);

    UNSAFE.putShortVolatile(new short[5], Unsafe.ARRAY_SHORT_BASE_OFFSET, (short) 0);
    UNSAFE.putShortVolatile(
        new short[5],
        Unsafe.ARRAY_SHORT_BASE_OFFSET + 4L * Unsafe.ARRAY_SHORT_INDEX_SCALE,
        (short) 0);

    UNSAFE.copyMemory(
        new byte[5],
        Unsafe.ARRAY_BYTE_BASE_OFFSET,
        new byte[5],
        Unsafe.ARRAY_BYTE_BASE_OFFSET + 3L * Unsafe.ARRAY_BYTE_INDEX_SCALE,
        2);
    UNSAFE.copyMemory(
        new byte[5],
        Unsafe.ARRAY_BYTE_BASE_OFFSET + 3L * Unsafe.ARRAY_BYTE_INDEX_SCALE,
        new byte[5],
        Unsafe.ARRAY_BYTE_BASE_OFFSET,
        2);

    UNSAFE.setMemory(new byte[5], Unsafe.ARRAY_BYTE_BASE_OFFSET, 2, (byte) 0);
    UNSAFE.setMemory(
        new byte[5],
        Unsafe.ARRAY_BYTE_BASE_OFFSET + 3L * Unsafe.ARRAY_BYTE_INDEX_SCALE,
        2,
        (byte) 0);

    // Assumes that byte[] address is aligned for 8-byte long access, or platform supports unaligned
    // access
    UNSAFE.getLong(new byte[8], Unsafe.ARRAY_BYTE_BASE_OFFSET);
    UNSAFE.getLong(
        new byte[16], Unsafe.ARRAY_BYTE_BASE_OFFSET + 8L * Unsafe.ARRAY_BYTE_INDEX_SCALE);

    long address = UNSAFE.allocateMemory(10);
    // Native memory access with `null` as object should be unaffected
    UNSAFE.putLong(null, address, 1);
    UNSAFE.getLong(null, address);
    UNSAFE.freeMemory(address);

    // Field access should be unaffected
    class Dummy {
      int i;
    }
    Field f = Dummy.class.getDeclaredField("i");
    long offset = UNSAFE.objectFieldOffset(f);
    UNSAFE.putInt(new Dummy(), offset, 1);
    UNSAFE.getInt(new Dummy(), offset);
  }
}
