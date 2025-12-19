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

import static com.code_intelligence.jazzer.mutation.mutator.lang.IntegralMutatorFactory.AbstractIntegralMutator.forceInRange;
import static java.lang.String.format;
import static java.util.Arrays.stream;

import com.code_intelligence.jazzer.mutation.annotation.ElementOf;
import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.AnnotatedType;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.IntStream;

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
    return tryCreatePrimitiveMutator((Class<?>) type.getType(), elementOf);
  }

  @FunctionalInterface
  interface IOFunction<T, R> {
    R apply(T t) throws IOException;
  }

  @FunctionalInterface
  interface IOBiConsumer<T, U> {
    void accept(T t, U u) throws IOException;
  }

  private static final class ElementOfMutator<T> extends SerializingMutator<T> {
    private final IOFunction<DataInputStream, T> read;
    private final IOBiConsumer<DataOutputStream, T> write;
    private final Set<T> dataSet;
    private final T[] data;
    private final Class<?> rawType;

    public ElementOfMutator(
        IOFunction<DataInputStream, T> read,
        IOBiConsumer<DataOutputStream, T> write,
        T[] data,
        Class<?> rawType) {
      this.read = read;
      this.write = write;
      this.dataSet = Set.of(data);
      this.data = data;
      this.rawType = rawType;
    }

    @Override
    public String toDebugString(Predicate<Debuggable> isInCycle) {
      return format("@ElementOf(size=%d) -> %s", data.length, rawType.getSimpleName());
    }

    @Override
    public T read(DataInputStream in) throws IOException {
      T value = read.apply(in);
      if (dataSet.contains(value)) {
        return value;
      }
      // Deterministic mapping from out-of-set values to in-set values
      int index = Math.abs(value.hashCode() % data.length);
      return data[index];
    }

    @Override
    public void write(T value, DataOutputStream out) throws IOException {
      write.accept(out, value);
    }

    @Override
    public T detach(T value) {
      return value; // primitive and immutable types only
    }

    @Override
    public T init(PseudoRandom prng) {
      return prng.pickIn(data);
    }

    @Override
    public T mutate(T value, PseudoRandom prng) {
      return prng.pickIn(data);
    }

    @Override
    public T crossOver(T value, T otherValue, PseudoRandom prng) {
      return prng.pickIn(data);
    }
  }

  private static Optional<SerializingMutator<?>> tryCreatePrimitiveMutator(
      Class<?> rawType, ElementOf elementOf) {
    if (rawType == byte.class || rawType == Byte.class) {
      return Optional.of(
          new ElementOfMutator<Byte>(
              DataInputStream::readByte,
              DataOutputStream::writeByte,
              getBytes(elementOf),
              rawType));
    } else if (rawType == short.class || rawType == Short.class) {
      return Optional.of(
          new ElementOfMutator<Short>(
              DataInputStream::readShort,
              DataOutputStream::writeShort,
              getShorts(elementOf),
              rawType));
    } else if (rawType == int.class || rawType == Integer.class) {
      return Optional.of(
          new ElementOfMutator<Integer>(
              DataInputStream::readInt,
              DataOutputStream::writeInt,
              getIntegers(elementOf),
              rawType));
    } else if (rawType == long.class || rawType == Long.class) {
      return Optional.of(
          new ElementOfMutator<Long>(
              DataInputStream::readLong,
              DataOutputStream::writeLong,
              getLongs(elementOf),
              rawType));
    } else if (rawType == char.class || rawType == Character.class) {
      return Optional.of(
          new ElementOfMutator<Character>(
              DataInputStream::readChar,
              DataOutputStream::writeChar,
              getChars(elementOf),
              rawType));
    } else if (rawType == float.class || rawType == Float.class) {
      return Optional.of(
          new ElementOfMutator<Float>(
              DataInputStream::readFloat,
              DataOutputStream::writeFloat,
              getFloats(elementOf),
              rawType));
    } else if (rawType == double.class || rawType == Double.class) {
      return Optional.of(
          new ElementOfMutator<Double>(
              DataInputStream::readDouble,
              DataOutputStream::writeDouble,
              getDoubles(elementOf),
              rawType));
    } else if (rawType == String.class) {
      String[] strings = elementOf.strings();
      int maxLength =
          stream(strings).mapToInt(s -> s.getBytes(StandardCharsets.UTF_8).length).max().orElse(0);
      return Optional.of(
          new ElementOfMutator<String>(
              (DataInputStream in) -> {
                int length = (int) forceInRange(in.readUnsignedShort(), 0, maxLength);
                byte[] byteData = new byte[length];
                in.readFully(byteData);
                return new String(byteData, StandardCharsets.UTF_8);
              },
              DataOutputStream::writeUTF,
              strings,
              rawType));
    }
    return Optional.empty();
  }

  private static Byte[] getBytes(ElementOf elementOf) {
    byte[] rawData = elementOf.bytes();
    return IntStream.range(0, rawData.length)
        .mapToObj(i -> rawData[i])
        .distinct()
        .toArray(Byte[]::new);
  }

  private static Short[] getShorts(ElementOf elementOf) {
    short[] rawData = elementOf.shorts();
    return IntStream.range(0, rawData.length)
        .mapToObj(i -> rawData[i])
        .distinct()
        .toArray(Short[]::new);
  }

  private static Integer[] getIntegers(ElementOf elementOf) {
    int[] rawData = elementOf.integers();
    return IntStream.range(0, rawData.length)
        .mapToObj(i -> rawData[i])
        .distinct()
        .toArray(Integer[]::new);
  }

  private static Long[] getLongs(ElementOf elementOf) {
    long[] rawData = elementOf.longs();
    return IntStream.range(0, rawData.length)
        .mapToObj(i -> rawData[i])
        .distinct()
        .toArray(Long[]::new);
  }

  private static Character[] getChars(ElementOf elementOf) {
    char[] rawData = elementOf.chars();
    return IntStream.range(0, rawData.length)
        .mapToObj(i -> rawData[i])
        .distinct()
        .toArray(Character[]::new);
  }

  private static Float[] getFloats(ElementOf elementOf) {
    float[] rawData = elementOf.floats();
    return IntStream.range(0, rawData.length)
        .mapToObj(i -> rawData[i])
        .distinct()
        .toArray(Float[]::new);
  }

  private static Double[] getDoubles(ElementOf elementOf) {
    double[] rawData = elementOf.doubles();
    return IntStream.range(0, rawData.length)
        .mapToObj(i -> rawData[i])
        .distinct()
        .toArray(Double[]::new);
  }
}
