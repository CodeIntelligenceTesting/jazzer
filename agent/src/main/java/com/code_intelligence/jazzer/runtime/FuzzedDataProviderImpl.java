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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.github.fmeum.rules_jni.RulesJni;

public class FuzzedDataProviderImpl implements FuzzedDataProvider {
  static {
    // The replayer loads a standalone version of the FuzzedDataProvider.
    if (System.getProperty("jazzer.is_replayer") == null) {
      RulesJni.loadLibrary("jazzer_driver", "/com/code_intelligence/jazzer/driver");
    }
    nativeInit();
  }

  public FuzzedDataProviderImpl() {}

  private static native void nativeInit();

  // Resets the FuzzedDataProvider state to read from the beginning to the end of the last fuzzer
  // input.
  public static native void reset();

  // Feeds new raw fuzzer input into the provider.
  // Note: Clients *must not* use this method if they also use the native FeedFuzzedDataProvider
  // method.
  public static native void feed(byte[] input);

  @Override public native boolean consumeBoolean();

  @Override public native boolean[] consumeBooleans(int maxLength);

  @Override public native byte consumeByte();

  @Override
  public byte consumeByte(byte min, byte max) {
    if (min > max) {
      throw new IllegalArgumentException(
          String.format("min must be <= max (got min: %d, max: %d)", min, max));
    }
    return consumeByteUnchecked(min, max);
  }

  @Override public native short consumeShort();

  @Override
  public short consumeShort(short min, short max) {
    if (min > max) {
      throw new IllegalArgumentException(
          String.format("min must be <= max (got min: %d, max: %d)", min, max));
    }
    return consumeShortUnchecked(min, max);
  }

  @Override public native short[] consumeShorts(int maxLength);

  @Override public native int consumeInt();

  @Override
  public int consumeInt(int min, int max) {
    if (min > max) {
      throw new IllegalArgumentException(
          String.format("min must be <= max (got min: %d, max: %d)", min, max));
    }
    return consumeIntUnchecked(min, max);
  }

  @Override public native int[] consumeInts(int maxLength);

  @Override public native long consumeLong();

  @Override
  public long consumeLong(long min, long max) {
    if (min > max) {
      throw new IllegalArgumentException(
          String.format("min must be <= max (got min: %d, max: %d)", min, max));
    }
    return consumeLongUnchecked(min, max);
  }

  @Override public native long[] consumeLongs(int maxLength);

  @Override public native float consumeFloat();

  @Override public native float consumeRegularFloat();

  @Override
  public float consumeRegularFloat(float min, float max) {
    if (min > max) {
      throw new IllegalArgumentException(
          String.format("min must be <= max (got min: %f, max: %f)", min, max));
    }
    return consumeRegularFloatUnchecked(min, max);
  }

  @Override public native float consumeProbabilityFloat();

  @Override public native double consumeDouble();

  @Override
  public double consumeRegularDouble(double min, double max) {
    if (min > max) {
      throw new IllegalArgumentException(
          String.format("min must be <= max (got min: %f, max: %f)", min, max));
    }
    return consumeRegularDoubleUnchecked(min, max);
  }

  @Override public native double consumeRegularDouble();

  @Override public native double consumeProbabilityDouble();

  @Override public native char consumeChar();

  @Override
  public char consumeChar(char min, char max) {
    if (min > max) {
      throw new IllegalArgumentException(
          String.format("min must be <= max (got min: %c, max: %c)", min, max));
    }
    return consumeCharUnchecked(min, max);
  }

  @Override public native char consumeCharNoSurrogates();

  @Override public native String consumeAsciiString(int maxLength);

  @Override public native String consumeString(int maxLength);

  @Override public native String consumeRemainingAsAsciiString();

  @Override public native String consumeRemainingAsString();

  @Override public native byte[] consumeBytes(int maxLength);

  @Override public native byte[] consumeRemainingAsBytes();

  @Override public native int remainingBytes();

  private native byte consumeByteUnchecked(byte min, byte max);
  private native short consumeShortUnchecked(short min, short max);
  private native char consumeCharUnchecked(char min, char max);
  private native int consumeIntUnchecked(int min, int max);
  private native long consumeLongUnchecked(long min, long max);
  private native float consumeRegularFloatUnchecked(float min, float max);
  private native double consumeRegularDoubleUnchecked(double min, double max);
}
