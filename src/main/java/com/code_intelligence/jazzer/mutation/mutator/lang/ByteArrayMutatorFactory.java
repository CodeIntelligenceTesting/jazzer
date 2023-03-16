/*
 * Copyright 2023 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.mutation.mutator.lang;

import static com.code_intelligence.jazzer.mutation.support.InputStreamSupport.readAllBytes;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.findFirstParentIfClass;

import com.code_intelligence.jazzer.mutation.annotation.WithLength;
import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.mutator.libfuzzer.LibFuzzerMutator;
import com.code_intelligence.jazzer.mutation.support.TypeSupport;
import com.google.errorprone.annotations.Immutable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.AnnotatedType;
import java.util.Arrays;
import java.util.Optional;
import java.util.function.Predicate;

final class ByteArrayMutatorFactory extends MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(AnnotatedType type, MutatorFactory factory) {
    Optional<WithLength> withLength = Optional.ofNullable(type.getAnnotation(WithLength.class));
    int minLength = withLength.map(WithLength::min).orElse(ByteArrayMutator.DEFAULT_MIN_LENGTH);
    int maxLength = withLength.map(WithLength::max).orElse(ByteArrayMutator.DEFAULT_MAX_LENGTH);

    return findFirstParentIfClass(type, byte[].class)
        .map(parent -> new ByteArrayMutator(minLength, maxLength));
  }

  @Immutable
  private static final class ByteArrayMutator extends SerializingMutator<byte[]> {
    private static final int DEFAULT_MIN_LENGTH = 0;
    private static final int DEFAULT_MAX_LENGTH = 1000;

    private final int minLength;

    private final int maxLength;

    private ByteArrayMutator(int min, int max) {
      this.minLength = min;
      this.maxLength = max;
    }

    @Override
    public byte[] read(DataInputStream in) throws IOException {
      // clamp the length to within min and max length
      int length = TypeSupport.clamp(in.readInt(), minLength, maxLength);
      byte[] bytes = new byte[length];
      in.readFully(bytes);
      return bytes;
    }

    @Override
    public byte[] readExclusive(InputStream in) throws IOException {
      return readAllBytes(in);
    }

    @Override
    public void write(byte[] value, DataOutputStream out) throws IOException {
      out.writeInt(value.length);
      out.write(value);
    }

    @Override
    public void writeExclusive(byte[] value, OutputStream out) throws IOException {
      out.write(value);
    }

    @Override
    public byte[] detach(byte[] value) {
      return Arrays.copyOf(value, value.length);
    }

    @Override
    public byte[] init(PseudoRandom prng) {
      int len = prng.closedRange(minLength, maxLength);
      byte[] bytes = new byte[len];
      prng.bytes(bytes);
      return bytes;
    }

    @Override
    public byte[] mutate(byte[] value, PseudoRandom prng) {
      // TODO: The way maxSizeIncrease is determined is just a heuristic and hasn't been
      //  benchmarked.
      byte[] mutated = LibFuzzerMutator.mutateDefault(value, Math.max(8, value.length / 16));

      // if the mutated array libfuzzer returns is too long or short, we truncate or extend it
      // respectively. if we extend it, then copyOf will fill leftover bytes with 0
      if (mutated.length > maxLength) {
        return Arrays.copyOf(mutated, maxLength);
      } else if (mutated.length < minLength) {
        return Arrays.copyOf(mutated, minLength);
      } else {
        return mutated;
      }
    }

    @Override
    public String toDebugString(Predicate<Debuggable> isInCycle) {
      return "byte[]";
    }
  }
}
