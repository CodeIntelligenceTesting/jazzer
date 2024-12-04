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

package com.code_intelligence.jazzer.api;

import java.io.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;

/**
 * Replays recorded FuzzedDataProvider invocations that were executed while fuzzing. Note: This
 * class is only meant to be used by Jazzer's generated reproducers.
 */
public final class CannedFuzzedDataProvider implements FuzzedDataProvider {
  private final Iterator<Object> nextReply;

  public CannedFuzzedDataProvider(String can) {
    byte[] rawIn = Base64.getDecoder().decode(can);
    ArrayList<Object> recordedReplies;
    try (ByteArrayInputStream byteStream = new ByteArrayInputStream(rawIn)) {
      try (ObjectInputStream objectStream = new ObjectInputStream(byteStream)) {
        recordedReplies = (ArrayList<Object>) objectStream.readObject();
      }
    } catch (IOException | ClassNotFoundException e) {
      throw new RuntimeException(e);
    }
    nextReply = recordedReplies.iterator();
  }

  public static CannedFuzzedDataProvider create(List<Object> objects) {
    try {
      try (ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
        try (ObjectOutputStream out = new ObjectOutputStream(bout)) {
          out.writeObject(new ArrayList<>(objects));
          String base64 = Base64.getEncoder().encodeToString(bout.toByteArray());
          return new CannedFuzzedDataProvider(base64);
        }
      }
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public boolean consumeBoolean() {
    return (boolean) nextReply.next();
  }

  @Override
  public boolean[] consumeBooleans(int maxLength) {
    return (boolean[]) nextReply.next();
  }

  @Override
  public byte consumeByte() {
    return (byte) nextReply.next();
  }

  @Override
  public byte consumeByte(byte min, byte max) {
    return (byte) nextReply.next();
  }

  @Override
  public short consumeShort() {
    return (short) nextReply.next();
  }

  @Override
  public short consumeShort(short min, short max) {
    return (short) nextReply.next();
  }

  @Override
  public short[] consumeShorts(int maxLength) {
    return (short[]) nextReply.next();
  }

  @Override
  public int consumeInt() {
    return (int) nextReply.next();
  }

  @Override
  public int consumeInt(int min, int max) {
    return (int) nextReply.next();
  }

  @Override
  public int[] consumeInts(int maxLength) {
    return (int[]) nextReply.next();
  }

  @Override
  public long consumeLong() {
    return (long) nextReply.next();
  }

  @Override
  public long consumeLong(long min, long max) {
    return (long) nextReply.next();
  }

  @Override
  public long[] consumeLongs(int maxLength) {
    return (long[]) nextReply.next();
  }

  @Override
  public float consumeFloat() {
    return (float) nextReply.next();
  }

  @Override
  public float consumeRegularFloat() {
    return (float) nextReply.next();
  }

  @Override
  public float consumeRegularFloat(float min, float max) {
    return (float) nextReply.next();
  }

  @Override
  public float consumeProbabilityFloat() {
    return (float) nextReply.next();
  }

  @Override
  public double consumeDouble() {
    return (double) nextReply.next();
  }

  @Override
  public double consumeRegularDouble(double min, double max) {
    return (double) nextReply.next();
  }

  @Override
  public double consumeRegularDouble() {
    return (double) nextReply.next();
  }

  @Override
  public double consumeProbabilityDouble() {
    return (double) nextReply.next();
  }

  @Override
  public char consumeChar() {
    return (char) nextReply.next();
  }

  @Override
  public char consumeChar(char min, char max) {
    return (char) nextReply.next();
  }

  @Override
  public char consumeCharNoSurrogates() {
    return (char) nextReply.next();
  }

  @Override
  public String consumeAsciiString(int maxLength) {
    return (String) nextReply.next();
  }

  @Override
  public String consumeString(int maxLength) {
    return (String) nextReply.next();
  }

  @Override
  public String consumeRemainingAsAsciiString() {
    return (String) nextReply.next();
  }

  @Override
  public String consumeRemainingAsString() {
    return (String) nextReply.next();
  }

  @Override
  public byte[] consumeBytes(int maxLength) {
    return (byte[]) nextReply.next();
  }

  @Override
  public byte[] consumeRemainingAsBytes() {
    return (byte[]) nextReply.next();
  }

  @Override
  public int remainingBytes() {
    return (int) nextReply.next();
  }
}
