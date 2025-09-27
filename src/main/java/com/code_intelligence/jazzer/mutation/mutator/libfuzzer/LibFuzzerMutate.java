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

package com.code_intelligence.jazzer.mutation.mutator.libfuzzer;

import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;

import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.Serializer;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public final class LibFuzzerMutate {
  /**
   * Key name to give to {@link System#setProperty(String, String)} to control the size of the
   * returned array for {@link #defaultMutateMock(byte[], int)}. Only used for testing purposes.
   */
  public static final String MOCK_SIZE_KEY = "libfuzzermutator.mock.newsize";

  public static byte[] mutateDefault(byte[] data, int maxSizeIncrease, PseudoRandom prng) {
    require(maxSizeIncrease >= 0);
    byte[] mutatedBytes;
    if (maxSizeIncrease == 0) {
      mutatedBytes = data;
    } else {
      mutatedBytes = Arrays.copyOf(data, data.length + maxSizeIncrease);
    }
    byte[] out = defaultMutate(mutatedBytes, data.length, prng);
    return out;
  }

  public static <T> T mutateDefault(
      T value, Serializer<T> serializer, int maxSizeIncrease, PseudoRandom prng) {
    require(maxSizeIncrease >= 0);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try {
      serializer.writeExclusive(value, out);
    } catch (IOException e) {
      throw new IllegalStateException(
          "writeExclusive is not expected to throw if the underlying stream doesn't", e);
    }

    byte[] mutatedBytes = mutateDefault(out.toByteArray(), maxSizeIncrease, prng);

    try {
      return serializer.readExclusive(new ByteArrayInputStream(mutatedBytes));
    } catch (IOException e) {
      throw new IllegalStateException(
          "readExclusive is not expected to throw if the underlying stream doesn't", e);
    }
  }

  private static byte[] defaultMutate(byte[] buffer, int size, PseudoRandom prng) {
    // TODO: implement byte [] mutator in Java and get rid of all JNI calls in the mutator
    // framework, including this mock
    //    if (Mutator.SHOULD_MOCK) {
    //      return defaultMutateMock(buffer, size);
    //    } else {
    return LibFuzzerMutatorFactory.LibFuzzerMutator.mutate(buffer, size, prng);
    // }
  }

  private static int defaultMutateMock(byte[] buffer, int size) {
    String newSizeProp = System.getProperty(MOCK_SIZE_KEY);
    int newSize = Math.min(buffer.length, size + 1);
    if (newSizeProp != null) {
      newSize = Integer.parseUnsignedInt(newSizeProp);
    }
    for (int i = 0; i < newSize; i++) {
      buffer[i] += (byte) (i + 1);
    }
    return newSize;
  }

  private LibFuzzerMutate() {}
}
