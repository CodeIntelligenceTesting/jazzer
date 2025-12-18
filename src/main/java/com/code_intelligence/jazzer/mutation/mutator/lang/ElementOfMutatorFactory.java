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

package com.code_intelligence.jazzer.mutation.mutator.lang;

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateIndices;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateThenMap;
import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static java.lang.String.format;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toList;

import com.code_intelligence.jazzer.mutation.annotation.ElementOf;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import java.lang.reflect.AnnotatedType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

final class ElementOfMutatorFactory implements MutatorFactory {
  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    ElementOf elementOf = type.getAnnotation(ElementOf.class);
    if (elementOf == null) {
      return Optional.empty();
    }
    if (!(type.getType() instanceof Class<?>)) {
      return Optional.empty();
    }
    Class<?> rawType = (Class<?>) type.getType();

    if (rawType == byte.class || rawType == Byte.class) {
      return Optional.of(
          elementOfMutator(boxBytes(elementOf.bytes()), "bytes", rawType.getSimpleName()));
    } else if (rawType == short.class || rawType == Short.class) {
      return Optional.of(
          elementOfMutator(boxShorts(elementOf.shorts()), "shorts", rawType.getSimpleName()));
    } else if (rawType == int.class || rawType == Integer.class) {
      return Optional.of(
          elementOfMutator(boxInts(elementOf.integers()), "integers", rawType.getSimpleName()));
    } else if (rawType == long.class || rawType == Long.class) {
      return Optional.of(
          elementOfMutator(boxLongs(elementOf.longs()), "longs", rawType.getSimpleName()));
    } else if (rawType == char.class || rawType == Character.class) {
      return Optional.of(
          elementOfMutator(boxChars(elementOf.chars()), "chars", rawType.getSimpleName()));
    } else if (rawType == float.class || rawType == Float.class) {
      return Optional.of(
          elementOfMutator(boxFloats(elementOf.floats()), "floats", rawType.getSimpleName()));
    } else if (rawType == double.class || rawType == Double.class) {
      return Optional.of(
          elementOfMutator(boxDoubles(elementOf.doubles()), "doubles", rawType.getSimpleName()));
    } else if (rawType == String.class) {
      return Optional.of(
          elementOfMutator(Arrays.asList(elementOf.strings()), "strings", rawType.getSimpleName()));
    }
    return Optional.empty();
  }

  private static <T> SerializingMutator<T> elementOfMutator(
      List<T> values, String fieldName, String targetTypeName) {
    require(
        !values.isEmpty(),
        format(
            "@ElementOf %s array must contain at least one value for %s",
            fieldName, targetTypeName));

    return mutateThenMap(
        mutateIndices(values.size()),
        values::get,
        value -> {
          int index = values.indexOf(value);
          require(
              index >= 0,
              "@ElementOf produced value not contained in the declared value set for "
                  + targetTypeName);
          return index;
        },
        isInCycle ->
            format("@ElementOf(%s, size=%d) -> %s", fieldName, values.size(), targetTypeName));
  }

  private static List<Byte> boxBytes(byte[] values) {
    List<Byte> result = new ArrayList<>(values.length);
    for (byte value : values) {
      result.add(value);
    }
    return result;
  }

  private static List<Short> boxShorts(short[] values) {
    List<Short> result = new ArrayList<>(values.length);
    for (short value : values) {
      result.add(value);
    }
    return result;
  }

  private static List<Integer> boxInts(int[] values) {
    return stream(values).boxed().collect(toList());
  }

  private static List<Long> boxLongs(long[] values) {
    return Arrays.stream(values).boxed().collect(toList());
  }

  private static List<Character> boxChars(char[] values) {
    List<Character> result = new ArrayList<>(values.length);
    for (char value : values) {
      result.add(value);
    }
    return result;
  }

  private static List<Float> boxFloats(float[] values) {
    List<Float> result = new ArrayList<>(values.length);
    for (float value : values) {
      result.add(value);
    }
    return result;
  }

  private static List<Double> boxDoubles(double[] values) {
    return Arrays.stream(values).boxed().collect(toList());
  }
}
