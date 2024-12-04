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

package com.code_intelligence.jazzer.mutation.mutator.collection;

import static com.code_intelligence.jazzer.mutation.mutator.collection.ChunkMutations.MutationAction.pickRandomMutationAction;
import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static com.code_intelligence.jazzer.mutation.support.PropertyConstraintSupport.propagatePropertyConstraints;
import static java.lang.Math.min;
import static java.lang.String.format;

import com.code_intelligence.jazzer.mutation.annotation.WithLength;
import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.RandomSupport;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.AnnotatedArrayType;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.Optional;
import java.util.function.Predicate;

final class ArrayMutatorFactory implements MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    if (!(type instanceof AnnotatedArrayType)) {
      return Optional.empty();
    }

    Optional<WithLength> withLength = Optional.ofNullable(type.getAnnotation(WithLength.class));
    int minLength = withLength.map(WithLength::min).orElse(ArrayMutator.DEFAULT_MIN_LENGTH);
    int maxLength = withLength.map(WithLength::max).orElse(ArrayMutator.DEFAULT_MAX_LENGTH);

    AnnotatedType elementType = ((AnnotatedArrayType) type).getAnnotatedGenericComponentType();
    AnnotatedType propagatedElementType = propagatePropertyConstraints(type, elementType);
    Class<?> propagatedElementClazz = (Class<?>) propagatedElementType.getType();
    return Optional.of(propagatedElementType)
        .flatMap(factory::tryCreate)
        .map(
            elementMutator ->
                new ArrayMutator<>(elementMutator, propagatedElementClazz, minLength, maxLength));
  }

  enum CrossOverAction {
    MIX,
    PROPAGATE,
    MUTATE;
  }

  private static final class ArrayMutator<T> extends SerializingMutator<T[]> {
    private static final int DEFAULT_MIN_LENGTH = 0;
    private static final int DEFAULT_MAX_LENGTH = 1000;

    private final SerializingMutator<T> elementMutator;
    private final Class<?> elementClazz;
    private final int minLength;
    private final int maxLength;

    ArrayMutator(
        SerializingMutator<T> elementMutator, Class<?> elementClazz, int minLength, int maxLength) {
      this.elementMutator = elementMutator;
      this.elementClazz = elementClazz;
      this.minLength = minLength;
      this.maxLength = maxLength;
      require(maxLength >= 1, format("WithLength#max=%d needs to be greater than 0", maxLength));
      require(
          minLength >= 0,
          format("WithLength#min=%d needs to be greater than or equal to 0", minLength));
    }

    @Override
    public T[] read(DataInputStream in) throws IOException {
      int size = RandomSupport.clamp(in.readInt(), minLength, maxLength);
      T[] array = (T[]) Array.newInstance(elementClazz, size);
      for (int i = 0; i < size; i++) {
        array[i] = elementMutator.read(in);
      }
      return array;
    }

    @Override
    public void write(T[] data, DataOutputStream out) throws IOException {
      out.writeInt(data.length);
      for (T element : data) {
        elementMutator.write(element, out);
      }
    }

    @Override
    public boolean hasFixedSize() {
      return false;
    }

    @Override
    public String toDebugString(Predicate<Debuggable> isInCycle) {
      return elementMutator.toDebugString(isInCycle) + "[]";
    }

    private int minInitialSize() {
      return minLength;
    }

    private int maxInitialSize() {
      if (elementMutator.requiresRecursionBreaking()) {
        return minInitialSize();
      }
      return min(maxLength, minLength + 1);
    }

    @Override
    public T[] detach(T[] value) {
      return Arrays.stream(value)
          .map(elementMutator::detach)
          .toArray(len -> (T[]) Array.newInstance(elementClazz, len));
    }

    @Override
    public T[] init(PseudoRandom prng) {
      int len = prng.closedRange(minInitialSize(), maxInitialSize());
      T[] array = (T[]) Array.newInstance(elementClazz, len);
      for (int i = 0; i < len; i++) {
        array[i] = elementMutator.init(prng);
      }
      return array;
    }

    @Override
    public T[] mutate(T[] value, PseudoRandom prng) {
      switch (pickRandomMutationAction(Arrays.asList(value), minLength, maxLength, prng)) {
        case DELETE_CHUNK:
          return eraseRandomChunk(value, prng);
        case INSERT_CHUNK:
          return insertRandomChunk(value, prng);
        case MUTATE_CHUNK:
          return mutateAtRandom(value, prng);
        default:
          throw new IllegalStateException("unsupported action");
      }
    }

    @Override
    public T[] crossOver(T[] arr, T[] otherArr, PseudoRandom prng) {
      // These crossover functions don't remove entries, that is handled by
      // the appropriate mutations on the result.
      switch (pickRandomCrossOverAction(arr, otherArr, prng)) {
        case MIX:
          return crossOverMix(arr, otherArr, prng);
        case PROPAGATE:
          crossOverPropagate(arr, otherArr, elementMutator, prng);
          return arr;
        case MUTATE:
          return mutate(arr, prng);
        default:
          throw new IllegalStateException("unsupported action");
      }
    }

    private T[] eraseRandomChunk(T[] value, PseudoRandom prng) {
      int valuesToErase = prng.closedRange(1, value.length - minLength);
      int newSize = value.length - valuesToErase;
      int from = prng.indexIn(newSize + 1);
      T[] out = (T[]) Array.newInstance(elementClazz, newSize);
      System.arraycopy(value, 0, out, 0, from);
      System.arraycopy(value, from + valuesToErase, out, from, newSize - from);
      return out;
    }

    private T[] insertRandomChunk(T[] value, PseudoRandom prng) {
      int valuesToInsert = prng.closedRange(1, maxLength - value.length);
      int newSize = value.length + valuesToInsert;
      int from = prng.indexIn(value.length + 1);
      T[] out = (T[]) Array.newInstance(elementClazz, newSize);
      System.arraycopy(value, 0, out, 0, from);
      for (int i = 0; i < valuesToInsert; i++) {
        out[from + i] = elementMutator.init(prng);
      }
      System.arraycopy(value, from, out, from + valuesToInsert, value.length - from);
      return out;
    }

    private T[] mutateAtRandom(T[] value, PseudoRandom prng) {
      int i = prng.indexIn(value.length);
      return mutateAtRandom(value, i, prng);
    }

    private T[] mutateAtRandom(T[] value, int idx, PseudoRandom prng) {
      value[idx] = elementMutator.mutate(value[idx], prng);
      return value;
    }

    /** Copy a random number of elements from {@code in} to {@code out} from/to given indices. */
    private int copyChunk(T[] in, int inPos, T[] out, int outPos, PseudoRandom prng) {
      if (inPos >= in.length) {
        return 0;
      }
      int extraLength = prng.closedRange(1, min(in.length - inPos, out.length - outPos));
      System.arraycopy(in, inPos, out, outPos, extraLength);
      return extraLength;
    }

    /** Copy as many elements as possible from {@code in} to {@code out} from/to given indices. */
    private int copyRemainingChunk(T[] in, int inPos, T[] out, int outPos) {
      if (inPos >= in.length) {
        return 0;
      }
      int extraLength = min(in.length - inPos, out.length - outPos);
      System.arraycopy(in, inPos, out, outPos, extraLength);
      return extraLength;
    }

    // Implementation inspired by libFuzzer:
    // https://github.com/llvm-mirror/compiler-rt/blob/master/lib/fuzzer/FuzzerCrossOver.cpp#L19
    private T[] crossOverMix(T[] arr, T[] otherArr, PseudoRandom prng) {
      final int minOutLength = min(arr.length, otherArr.length);
      final int maxOutLength = arr.length + otherArr.length;
      int newLength =
          RandomSupport.clamp(prng.closedRange(minOutLength, maxOutLength), minLength, maxLength);
      T[] out = (T[]) Array.newInstance(elementClazz, newLength);
      int outPos = 0;
      int arrPos = 0;
      int otherArrPos = 0;
      while (newLength > 0) {
        if (arrPos < arr.length && otherArrPos < otherArr.length) {
          // Both arrays still have elements to copy: choose one randomly.
          if (prng.choice()) {
            int extraLength = copyChunk(arr, arrPos, out, outPos, prng);
            arrPos += extraLength;
            outPos += extraLength;
            newLength -= extraLength;
          } else {
            int extraLength = copyChunk(otherArr, otherArrPos, out, outPos, prng);
            otherArrPos += extraLength;
            outPos += extraLength;
            newLength -= extraLength;
          }
        } else if (arrPos < arr.length) {
          // Only the first array is exhausted: copy the rest from it.
          int extraLength = copyChunk(arr, arrPos, out, outPos, prng);
          arrPos += extraLength;
          outPos += extraLength;
          newLength -= extraLength;
        } else if (otherArrPos < otherArr.length) {
          // Only the second array is exhausted: copy the rest from it.
          int extraLength = copyRemainingChunk(otherArr, otherArrPos, out, outPos);
          otherArrPos += extraLength;
          outPos += extraLength;
          newLength -= extraLength;
        }
        // The length of the out array cannot be greater than the sum of the lengths of the two
        // input arrays.
      }
      return out;
    }

    /**
     * Crossover a randomly picked element from {@code array} with another randomly picked element
     * from {@code otherValue}.
     */
    private void crossOverPropagate(
        T[] value, T[] otherValue, SerializingMutator<T> elementMutator, PseudoRandom prng) {
      int i = prng.indexIn(value.length);
      int j = prng.indexIn(otherValue.length);
      value[i] = elementMutator.crossOver(value[i], otherValue[j], prng);
    }

    private CrossOverAction pickRandomCrossOverAction(T[] arr, T[] otherArr, PseudoRandom prng) {
      if (arr.length > 0 && otherArr.length > 0) {
        // 70% propagate, 30% mix
        return prng.indexIn(10) < 7 ? CrossOverAction.PROPAGATE : CrossOverAction.MIX;
      } else {
        // Mutate to avoid a NOOP, which we know won't give us any new coverage.
        return CrossOverAction.MUTATE;
      }
    }
  }
}
