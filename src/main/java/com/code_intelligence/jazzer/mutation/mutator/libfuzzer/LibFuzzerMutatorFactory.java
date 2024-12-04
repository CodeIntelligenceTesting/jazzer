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

import static com.code_intelligence.jazzer.mutation.support.InputStreamSupport.readAllBytes;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.findFirstParentIfClass;

import com.code_intelligence.jazzer.mutation.annotation.WithLength;
import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.RandomSupport;
import com.google.errorprone.annotations.CheckReturnValue;
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

public final class LibFuzzerMutatorFactory {
  private static final int DEFAULT_MIN_LENGTH = 0;
  private static final int DEFAULT_MAX_LENGTH = 1000;

  @CheckReturnValue
  public static Optional<SerializingMutator<?>> tryCreate(AnnotatedType type) {
    Optional<WithLength> withLength = Optional.ofNullable(type.getAnnotation(WithLength.class));
    int minLength = withLength.map(WithLength::min).orElse(DEFAULT_MIN_LENGTH);
    int maxLength = withLength.map(WithLength::max).orElse(DEFAULT_MAX_LENGTH);

    return findFirstParentIfClass(type, byte[].class)
        .map(parent -> new LibFuzzerMutator(minLength, maxLength));
  }

  @Immutable
  private static final class LibFuzzerMutator extends SerializingMutator<byte[]> {
    private final int minLength;

    private final int maxLength;

    private LibFuzzerMutator(int min, int max) {
      this.minLength = min;
      this.maxLength = max;
    }

    @Override
    public byte[] read(DataInputStream in) throws IOException {
      int length = RandomSupport.clamp(in.readInt(), minLength, maxLength);
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
      int len = prng.closedRange(minInitialSize(), maxInitialSize());
      byte[] bytes = new byte[len];
      prng.bytes(bytes);
      return bytes;
    }

    private int minInitialSize() {
      return minLength;
    }

    private int maxInitialSize() {
      // Allow some variation in length, but keep the initial elements well within reach of each
      // other via a single mutation based on a Table of Recent Compares (ToRC) entry, which is
      // currently limited to 64 bytes.
      // Compared to List<T>, byte arrays can't result in recursive type hierarchies and thus don't
      // to limit their expected initial size to be <= 1.
      return Math.min(minLength + 16, maxLength);
    }

    @Override
    public byte[] mutate(byte[] value, PseudoRandom prng) {
      int maxLengthIncrease = maxLength - value.length;
      byte[] mutated = LibFuzzerMutate.mutateDefault(value, maxLengthIncrease);
      return enforceLength(mutated);
    }

    private byte[] enforceLength(byte[] mutated) {
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
    public byte[] crossOver(byte[] value, byte[] otherValue, PseudoRandom prng) {
      // Passed in values are expected to already honor the min/max length constraints.
      // As there does not seem to be an easy way to call libFuzzer's internal cross over
      // algorithm, it is re-implemented in native Java. The algorithm is based on:
      // https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/fuzzer/FuzzerMutate.cpp#L440
      // https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/fuzzer/FuzzerCrossOver.cpp#L19
      //

      if (value.length == 0 || otherValue.length == 0) {
        return value;
      }

      // TODO: Measure if this is fast enough.
      byte[] out = null;
      while (out == null) {
        switch (prng.indexIn(3)) {
          case 0:
            out = intersect(value, otherValue, prng);
            break;
          case 1:
            out = insertPart(value, otherValue, prng);
            break;
          case 2:
            out = overwritePart(value, otherValue, prng);
            break;
          default:
            throw new AssertionError("Invalid cross over function.");
        }
      }
      return enforceLength(out);
    }

    private static byte[] intersect(byte[] value, byte[] otherValue, PseudoRandom prng) {
      int maxOutSize = prng.closedRange(0, Math.min(value.length, otherValue.length));
      byte[] out = new byte[maxOutSize];
      int outPos = 0;
      int valuePos = 0;
      int otherValuePos = 0;
      boolean usingFirstValue = true;
      while (outPos < out.length) {
        if (usingFirstValue && valuePos < value.length) {
          int extraSize = rndArraycopy(value, valuePos, out, outPos, prng);
          outPos += extraSize;
          valuePos += extraSize;
        } else if (!usingFirstValue && otherValuePos < otherValue.length) {
          int extraSize = rndArraycopy(otherValue, otherValuePos, out, outPos, prng);
          outPos += extraSize;
          otherValuePos += extraSize;
        }
        usingFirstValue = !usingFirstValue;
      }
      return out;
    }

    private static int rndArraycopy(
        byte[] val, int valPos, byte[] out, int outPos, PseudoRandom prng) {
      int outSizeLeft = out.length - outPos;
      int inSizeLeft = val.length - valPos;
      int maxExtraSize = Math.min(outSizeLeft, inSizeLeft);
      int extraSize = prng.closedRange(0, maxExtraSize);
      System.arraycopy(val, valPos, out, outPos, extraSize);
      return extraSize;
    }

    private static byte[] insertPart(byte[] value, byte[] otherValue, PseudoRandom prng) {
      int copySize = prng.closedRange(1, otherValue.length);
      int f = otherValue.length - copySize;
      int fromPos = f == 0 ? 0 : prng.indexIn(f);
      int toPos = prng.indexIn(value.length);
      int tailSize = value.length - toPos;

      byte[] out = new byte[value.length + copySize];
      System.arraycopy(value, 0, out, 0, toPos);
      System.arraycopy(otherValue, fromPos, out, toPos, copySize);
      System.arraycopy(value, toPos, out, toPos + copySize, tailSize);
      return out;
    }

    private static byte[] overwritePart(byte[] value, byte[] otherValue, PseudoRandom prng) {
      int toPos = prng.indexIn(value.length);
      int copySize = Math.min(prng.closedRange(1, value.length - toPos), otherValue.length);
      int f = otherValue.length - copySize;
      int fromPos = f == 0 ? 0 : prng.indexIn(f);
      System.arraycopy(otherValue, fromPos, value, toPos, copySize);
      return value;
    }

    @Override
    public boolean hasFixedSize() {
      return false;
    }

    @Override
    public String toDebugString(Predicate<Debuggable> isInCycle) {
      return "byte[]";
    }
  }
}
