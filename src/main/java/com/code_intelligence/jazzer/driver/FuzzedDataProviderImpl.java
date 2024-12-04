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

package com.code_intelligence.jazzer.driver;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.utils.UnsafeProvider;
import com.github.fmeum.rules_jni.RulesJni;
import sun.misc.Unsafe;

public class FuzzedDataProviderImpl implements FuzzedDataProvider, AutoCloseable {
  static {
    RulesJni.loadLibrary("jazzer_fuzzed_data_provider", "/com/code_intelligence/jazzer/driver");
    nativeInit();
  }

  private static native void nativeInit();

  private final byte[] javaData;
  private long originalDataPtr;
  private int originalRemainingBytes;

  // Accessed in fuzzed_data_provider.cpp.
  private long dataPtr;
  private int remainingBytes;

  private FuzzedDataProviderImpl(long dataPtr, int remainingBytes, byte[] javaData) {
    this.javaData = javaData;
    this.originalDataPtr = dataPtr;
    this.dataPtr = dataPtr;
    this.originalRemainingBytes = remainingBytes;
    this.remainingBytes = remainingBytes;
  }

  /**
   * Creates a {@link FuzzedDataProvider} that consumes bytes from an already existing native array.
   *
   * <ul>
   *   <li>{@link #close()} <b>must</b> be called on instances created with this method to free the
   *       native copy of the Java {@code byte} array.
   *   <li>{@link #setNativeData(long, int)} <b>must not</b> be called on instances created with
   *       this method.
   *
   * @param data the raw bytes used as input
   * @return a {@link FuzzedDataProvider} backed by {@code data}
   */
  public static FuzzedDataProviderImpl withJavaData(byte[] data) {
    return new FuzzedDataProviderImpl(allocateNativeCopy(data), data.length, data);
  }

  /**
   * Creates a {@link FuzzedDataProvider} that consumes bytes from an already existing native array.
   *
   * <p>The backing array can be set at any time using {@link #setNativeData(long, int)} and is
   * initially empty.
   *
   * @return a {@link FuzzedDataProvider} backed by an empty array.
   */
  public static FuzzedDataProviderImpl withNativeData() {
    return new FuzzedDataProviderImpl(0, 0, null);
  }

  /**
   * Replaces the current native backing array.
   *
   * <p><b>Must not</b> be called on instances created with {@link #withJavaData(byte[])}.
   *
   * @param dataPtr a native pointer to the new backing array
   * @param dataLength the length of the new backing array
   */
  public void setNativeData(long dataPtr, int dataLength) {
    this.originalDataPtr = dataPtr;
    this.dataPtr = dataPtr;
    this.originalRemainingBytes = dataLength;
    this.remainingBytes = dataLength;
  }

  /**
   * Returns the Java byte array used to construct the instance, or null if it was created with
   * {@link FuzzedDataProviderImpl#withNativeData()};
   */
  public byte[] getJavaData() {
    return javaData;
  }

  /**
   * Resets the FuzzedDataProvider state to read from the beginning to the end of its current
   * backing item.
   */
  public void reset() {
    dataPtr = originalDataPtr;
    remainingBytes = originalRemainingBytes;
  }

  /**
   * Releases native memory allocated for this instance (if any).
   *
   * <p>While the instance should not be used after this method returns, no usage of {@link
   * FuzzedDataProvider} methods can result in memory corruption.
   */
  @Override
  public void close() {
    if (originalDataPtr == 0) {
      return;
    }
    // We own the native memory iff the instance was created backed by a Java byte array.
    if (javaData != null) {
      UNSAFE.freeMemory(originalDataPtr);
    }
    // Prevent double-frees and use-after-frees by effectively making all methods no-ops after
    // close() has been called.
    originalDataPtr = 0;
    originalRemainingBytes = 0;
    dataPtr = 0;
    remainingBytes = 0;
  }

  private static final Unsafe UNSAFE = UnsafeProvider.getUnsafe();
  private static final long BYTE_ARRAY_OFFSET = UNSAFE.arrayBaseOffset(byte[].class);

  private static long allocateNativeCopy(byte[] data) {
    long nativeCopy = UNSAFE.allocateMemory(data.length);
    UNSAFE.copyMemory(data, BYTE_ARRAY_OFFSET, null, nativeCopy, data.length);
    return nativeCopy;
  }

  @Override
  public native boolean consumeBoolean();

  @Override
  public native boolean[] consumeBooleans(int maxLength);

  @Override
  public native byte consumeByte();

  @Override
  public byte consumeByte(byte min, byte max) {
    if (min > max) {
      throw new IllegalArgumentException(
          String.format("min must be <= max (got min: %d, max: %d)", min, max));
    }
    return consumeByteUnchecked(min, max);
  }

  @Override
  public native short consumeShort();

  @Override
  public short consumeShort(short min, short max) {
    if (min > max) {
      throw new IllegalArgumentException(
          String.format("min must be <= max (got min: %d, max: %d)", min, max));
    }
    return consumeShortUnchecked(min, max);
  }

  @Override
  public native short[] consumeShorts(int maxLength);

  @Override
  public native int consumeInt();

  @Override
  public int consumeInt(int min, int max) {
    if (min > max) {
      throw new IllegalArgumentException(
          String.format("min must be <= max (got min: %d, max: %d)", min, max));
    }
    return consumeIntUnchecked(min, max);
  }

  @Override
  public native int[] consumeInts(int maxLength);

  @Override
  public native long consumeLong();

  @Override
  public long consumeLong(long min, long max) {
    if (min > max) {
      throw new IllegalArgumentException(
          String.format("min must be <= max (got min: %d, max: %d)", min, max));
    }
    return consumeLongUnchecked(min, max);
  }

  @Override
  public native long[] consumeLongs(int maxLength);

  @Override
  public native float consumeFloat();

  @Override
  public native float consumeRegularFloat();

  @Override
  public float consumeRegularFloat(float min, float max) {
    if (!Float.isFinite(min)) {
      throw new IllegalArgumentException("min must be a regular float");
    }
    if (!Float.isFinite(max)) {
      throw new IllegalArgumentException("max must be a regular float");
    }
    if (min > max) {
      throw new IllegalArgumentException(
          String.format("min must be <= max (got min: %f, max: %f)", min, max));
    }
    return consumeRegularFloatUnchecked(min, max);
  }

  @Override
  public native float consumeProbabilityFloat();

  @Override
  public native double consumeDouble();

  @Override
  public double consumeRegularDouble(double min, double max) {
    if (!Double.isFinite(min)) {
      throw new IllegalArgumentException("min must be a regular double");
    }
    if (!Double.isFinite(max)) {
      throw new IllegalArgumentException("max must be a regular double");
    }
    if (min > max) {
      throw new IllegalArgumentException(
          String.format("min must be <= max (got min: %f, max: %f)", min, max));
    }
    return consumeRegularDoubleUnchecked(min, max);
  }

  @Override
  public native double consumeRegularDouble();

  @Override
  public native double consumeProbabilityDouble();

  @Override
  public native char consumeChar();

  @Override
  public char consumeChar(char min, char max) {
    if (min > max) {
      throw new IllegalArgumentException(
          String.format("min must be <= max (got min: %c, max: %c)", min, max));
    }
    return consumeCharUnchecked(min, max);
  }

  @Override
  public native char consumeCharNoSurrogates();

  @Override
  public native String consumeAsciiString(int maxLength);

  @Override
  public native String consumeString(int maxLength);

  @Override
  public native String consumeRemainingAsAsciiString();

  @Override
  public native String consumeRemainingAsString();

  @Override
  public native byte[] consumeBytes(int maxLength);

  @Override
  public native byte[] consumeRemainingAsBytes();

  @Override
  public native int remainingBytes();

  private native byte consumeByteUnchecked(byte min, byte max);

  private native short consumeShortUnchecked(short min, short max);

  private native char consumeCharUnchecked(char min, char max);

  private native int consumeIntUnchecked(int min, int max);

  private native long consumeLongUnchecked(long min, long max);

  private native float consumeRegularFloatUnchecked(float min, float max);

  private native double consumeRegularDoubleUnchecked(double min, double max);
}
