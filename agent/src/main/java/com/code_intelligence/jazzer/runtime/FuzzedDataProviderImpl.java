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

public class FuzzedDataProviderImpl implements FuzzedDataProvider {
  public FuzzedDataProviderImpl() {}

  @Override public native boolean consumeBoolean();

  @Override public native boolean[] consumeBooleans(int maxLength);

  @Override public native byte consumeByte();

  @Override public native byte consumeByte(byte min, byte max);

  @Override public native short consumeShort();

  @Override public native short consumeShort(short min, short max);

  @Override public native short[] consumeShorts(int maxLength);

  @Override public native int consumeInt();

  @Override public native int consumeInt(int min, int max);

  @Override public native int[] consumeInts(int maxLength);

  @Override public native long consumeLong();

  @Override public native long consumeLong(long min, long max);

  @Override public native long[] consumeLongs(int maxLength);

  @Override public native float consumeFloat();

  @Override public native float consumeRegularFloat();

  @Override public native float consumeRegularFloat(float min, float max);

  @Override public native float consumeProbabilityFloat();

  @Override public native double consumeDouble();

  @Override public native double consumeRegularDouble(double min, double max);

  @Override public native double consumeRegularDouble();

  @Override public native double consumeProbabilityDouble();

  @Override public native char consumeChar();

  @Override public native char consumeChar(char min, char max);

  @Override public native char consumeCharNoSurrogates();

  @Override public native String consumeAsciiString(int maxLength);

  @Override public native String consumeString(int maxLength);

  @Override public native String consumeRemainingAsAsciiString();

  @Override public native String consumeRemainingAsString();

  @Override public native byte[] consumeBytes(int maxLength);

  @Override public native byte[] consumeRemainingAsBytes();

  @Override public native int remainingBytes();
}
