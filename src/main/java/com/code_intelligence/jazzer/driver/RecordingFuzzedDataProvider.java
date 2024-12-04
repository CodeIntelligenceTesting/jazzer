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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Base64;

// Wraps the native FuzzedDataProviderImpl and serializes all its return values
// into a Base64-encoded string.
public final class RecordingFuzzedDataProvider implements FuzzedDataProvider {
  private final FuzzedDataProvider target;
  private final ArrayList<Object> recordedReplies = new ArrayList<>();

  private RecordingFuzzedDataProvider(FuzzedDataProvider target) {
    this.target = target;
  }

  public static FuzzedDataProvider makeFuzzedDataProviderProxy(FuzzedDataProvider target) {
    return new RecordingFuzzedDataProvider(target);
  }

  public static String serializeFuzzedDataProviderProxy(FuzzedDataProvider proxy)
      throws IOException {
    return ((RecordingFuzzedDataProvider) proxy).serialize();
  }

  private <T> T recordAndReturn(T object) {
    recordedReplies.add(object);
    return object;
  }

  private String serialize() throws IOException {
    byte[] rawOut;
    try (ByteArrayOutputStream byteStream = new ByteArrayOutputStream()) {
      try (ObjectOutputStream objectStream = new ObjectOutputStream(byteStream)) {
        objectStream.writeObject(recordedReplies);
      }
      rawOut = byteStream.toByteArray();
    }
    return Base64.getEncoder().encodeToString(rawOut);
  }

  @Override
  public boolean consumeBoolean() {
    return recordAndReturn(target.consumeBoolean());
  }

  @Override
  public boolean[] consumeBooleans(int maxLength) {
    return recordAndReturn(target.consumeBooleans(maxLength));
  }

  @Override
  public byte consumeByte() {
    return recordAndReturn(target.consumeByte());
  }

  @Override
  public byte consumeByte(byte min, byte max) {
    return recordAndReturn(target.consumeByte(min, max));
  }

  @Override
  public byte[] consumeBytes(int maxLength) {
    return recordAndReturn(target.consumeBytes(maxLength));
  }

  @Override
  public byte[] consumeRemainingAsBytes() {
    return recordAndReturn(target.consumeRemainingAsBytes());
  }

  @Override
  public short consumeShort() {
    return recordAndReturn(target.consumeShort());
  }

  @Override
  public short consumeShort(short min, short max) {
    return recordAndReturn(target.consumeShort(min, max));
  }

  @Override
  public short[] consumeShorts(int maxLength) {
    return recordAndReturn(target.consumeShorts(maxLength));
  }

  @Override
  public int consumeInt() {
    return recordAndReturn(target.consumeInt());
  }

  @Override
  public int consumeInt(int min, int max) {
    return recordAndReturn(target.consumeInt(min, max));
  }

  @Override
  public int[] consumeInts(int maxLength) {
    return recordAndReturn(target.consumeInts(maxLength));
  }

  @Override
  public long consumeLong() {
    return recordAndReturn(target.consumeLong());
  }

  @Override
  public long consumeLong(long min, long max) {
    return recordAndReturn(target.consumeLong(min, max));
  }

  @Override
  public long[] consumeLongs(int maxLength) {
    return recordAndReturn(target.consumeLongs(maxLength));
  }

  @Override
  public float consumeFloat() {
    return recordAndReturn(target.consumeFloat());
  }

  @Override
  public float consumeRegularFloat() {
    return recordAndReturn(target.consumeRegularFloat());
  }

  @Override
  public float consumeRegularFloat(float min, float max) {
    return recordAndReturn(target.consumeRegularFloat(min, max));
  }

  @Override
  public float consumeProbabilityFloat() {
    return recordAndReturn(target.consumeProbabilityFloat());
  }

  @Override
  public double consumeDouble() {
    return recordAndReturn(target.consumeDouble());
  }

  @Override
  public double consumeRegularDouble() {
    return recordAndReturn(target.consumeRegularDouble());
  }

  @Override
  public double consumeRegularDouble(double min, double max) {
    return recordAndReturn(target.consumeRegularDouble(min, max));
  }

  @Override
  public double consumeProbabilityDouble() {
    return recordAndReturn(target.consumeProbabilityDouble());
  }

  @Override
  public char consumeChar() {
    return recordAndReturn(target.consumeChar());
  }

  @Override
  public char consumeChar(char min, char max) {
    return recordAndReturn(target.consumeChar(min, max));
  }

  @Override
  public char consumeCharNoSurrogates() {
    return recordAndReturn(target.consumeCharNoSurrogates());
  }

  @Override
  public String consumeString(int maxLength) {
    return recordAndReturn(target.consumeString(maxLength));
  }

  @Override
  public String consumeRemainingAsString() {
    return recordAndReturn(target.consumeRemainingAsString());
  }

  @Override
  public String consumeAsciiString(int maxLength) {
    return recordAndReturn(target.consumeAsciiString(maxLength));
  }

  @Override
  public String consumeRemainingAsAsciiString() {
    return recordAndReturn(target.consumeRemainingAsAsciiString());
  }

  @Override
  public int remainingBytes() {
    return recordAndReturn(target.remainingBytes());
  }
}
