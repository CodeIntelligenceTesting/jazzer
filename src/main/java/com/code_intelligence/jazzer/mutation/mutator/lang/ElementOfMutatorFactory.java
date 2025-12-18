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

import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static java.lang.String.format;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toList;

import com.code_intelligence.jazzer.mutation.annotation.ElementOf;
import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.InputStreamSupport;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.AnnotatedType;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;

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
          elementOfMutator(
              boxBytes(elementOf.bytes()), "bytes", rawType.getSimpleName(), BYTE_SERIALIZER));
    } else if (rawType == short.class || rawType == Short.class) {
      return Optional.of(
          elementOfMutator(
              boxShorts(elementOf.shorts()), "shorts", rawType.getSimpleName(), SHORT_SERIALIZER));
    } else if (rawType == int.class || rawType == Integer.class) {
      return Optional.of(
          elementOfMutator(
              boxInts(elementOf.integers()), "integers", rawType.getSimpleName(), INT_SERIALIZER));
    } else if (rawType == long.class || rawType == Long.class) {
      return Optional.of(
          elementOfMutator(
              boxLongs(elementOf.longs()), "longs", rawType.getSimpleName(), LONG_SERIALIZER));
    } else if (rawType == char.class || rawType == Character.class) {
      return Optional.of(
          elementOfMutator(
              boxChars(elementOf.chars()), "chars", rawType.getSimpleName(), CHAR_SERIALIZER));
    } else if (rawType == float.class || rawType == Float.class) {
      return Optional.of(
          elementOfMutator(
              boxFloats(elementOf.floats()), "floats", rawType.getSimpleName(), FLOAT_SERIALIZER));
    } else if (rawType == double.class || rawType == Double.class) {
      return Optional.of(
          elementOfMutator(
              boxDoubles(elementOf.doubles()),
              "doubles",
              rawType.getSimpleName(),
              DOUBLE_SERIALIZER));
    } else if (rawType == String.class) {
      return Optional.of(
          elementOfMutator(
              Arrays.asList(elementOf.strings()),
              "strings",
              rawType.getSimpleName(),
              STRING_SERIALIZER));
    }
    return Optional.empty();
  }

  private static <T> SerializingMutator<T> elementOfMutator(
      List<T> values, String fieldName, String targetTypeName, ValueSerializer<T> serializer) {
    require(
        !values.isEmpty(),
        format(
            "@ElementOf %s array must contain at least one value for %s",
            fieldName, targetTypeName));
    // Build index map for O(1) lookups
    Map<T, Integer> valueToIndex = new HashMap<>();
    for (int i = 0; i < values.size(); i++) {
      valueToIndex.put(values.get(i), i);
    }
    return new SerializingMutator<T>() {
      @Override
      public T read(DataInputStream in) throws IOException {
        T value = serializer.read(in);
        // If the value is in the allowed set, use it; otherwise use the first value
        return valueToIndex.containsKey(value) ? value : values.get(0);
      }

      @Override
      public void write(T value, DataOutputStream out) throws IOException {
        serializer.write(value, out);
      }

      @Override
      public T readExclusive(InputStream in) throws IOException {
        T value = serializer.readExclusive(in);
        return valueToIndex.containsKey(value) ? value : values.get(0);
      }

      @Override
      public void writeExclusive(T value, OutputStream out) throws IOException {
        serializer.writeExclusive(value, out);
      }

      @Override
      public T detach(T value) {
        return value;
      }

      @Override
      public T init(PseudoRandom prng) {
        return values.get(prng.indexIn(values));
      }

      @Override
      public T mutate(T value, PseudoRandom prng) {
        // With only one value, return the same value (no-op mutation)
        if (values.size() == 1) {
          return value;
        }
        // Pick a different value from the set
        return values.get(prng.otherIndexIn(values.size(), valueToIndex.get(value)));
      }

      @Override
      public T crossOver(T value, T otherValue, PseudoRandom prng) {
        return prng.choice() ? value : otherValue;
      }

      @Override
      public boolean hasFixedSize() {
        return serializer.hasFixedSize();
      }

      @Override
      public String toDebugString(Predicate<Debuggable> isInCycle) {
        return format("@ElementOf<%s>[%d]", targetTypeName, values.size());
      }
    };
  }

  private interface ValueSerializer<T> {
    T read(DataInputStream in) throws IOException;

    void write(T value, DataOutputStream out) throws IOException;

    boolean hasFixedSize();

    default T readExclusive(InputStream in) throws IOException {
      return read(new DataInputStream(in));
    }

    default void writeExclusive(T value, OutputStream out) throws IOException {
      write(value, new DataOutputStream(out));
    }
  }

  private static final ValueSerializer<Byte> BYTE_SERIALIZER =
      new ValueSerializer<Byte>() {
        @Override
        public Byte read(DataInputStream in) throws IOException {
          return in.readByte();
        }

        @Override
        public void write(Byte value, DataOutputStream out) throws IOException {
          out.writeByte(value);
        }

        @Override
        public boolean hasFixedSize() {
          return true;
        }
      };

  private static final ValueSerializer<Short> SHORT_SERIALIZER =
      new ValueSerializer<Short>() {
        @Override
        public Short read(DataInputStream in) throws IOException {
          return in.readShort();
        }

        @Override
        public void write(Short value, DataOutputStream out) throws IOException {
          out.writeShort(value);
        }

        @Override
        public boolean hasFixedSize() {
          return true;
        }
      };

  private static final ValueSerializer<Integer> INT_SERIALIZER =
      new ValueSerializer<Integer>() {
        @Override
        public Integer read(DataInputStream in) throws IOException {
          return in.readInt();
        }

        @Override
        public void write(Integer value, DataOutputStream out) throws IOException {
          out.writeInt(value);
        }

        @Override
        public boolean hasFixedSize() {
          return true;
        }
      };

  private static final ValueSerializer<Long> LONG_SERIALIZER =
      new ValueSerializer<Long>() {
        @Override
        public Long read(DataInputStream in) throws IOException {
          return in.readLong();
        }

        @Override
        public void write(Long value, DataOutputStream out) throws IOException {
          out.writeLong(value);
        }

        @Override
        public boolean hasFixedSize() {
          return true;
        }
      };

  private static final ValueSerializer<Character> CHAR_SERIALIZER =
      new ValueSerializer<Character>() {
        @Override
        public Character read(DataInputStream in) throws IOException {
          return in.readChar();
        }

        @Override
        public void write(Character value, DataOutputStream out) throws IOException {
          out.writeChar(value);
        }

        @Override
        public boolean hasFixedSize() {
          return true;
        }
      };

  private static final ValueSerializer<Float> FLOAT_SERIALIZER =
      new ValueSerializer<Float>() {
        @Override
        public Float read(DataInputStream in) throws IOException {
          return in.readFloat();
        }

        @Override
        public void write(Float value, DataOutputStream out) throws IOException {
          out.writeFloat(value);
        }

        @Override
        public boolean hasFixedSize() {
          return true;
        }
      };

  private static final ValueSerializer<Double> DOUBLE_SERIALIZER =
      new ValueSerializer<Double>() {
        @Override
        public Double read(DataInputStream in) throws IOException {
          return in.readDouble();
        }

        @Override
        public void write(Double value, DataOutputStream out) throws IOException {
          out.writeDouble(value);
        }

        @Override
        public boolean hasFixedSize() {
          return true;
        }
      };

  private static final ValueSerializer<String> STRING_SERIALIZER =
      new ValueSerializer<String>() {
        @Override
        public String read(DataInputStream in) throws IOException {
          int length = Math.max(0, in.readInt());
          byte[] bytes = new byte[length];
          in.readFully(bytes);
          return new String(bytes, StandardCharsets.UTF_8);
        }

        @Override
        public void write(String value, DataOutputStream out) throws IOException {
          byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
          out.writeInt(bytes.length);
          out.write(bytes);
        }

        @Override
        public String readExclusive(InputStream in) throws IOException {
          return new String(InputStreamSupport.readAllBytes(in), StandardCharsets.UTF_8);
        }

        @Override
        public void writeExclusive(String value, OutputStream out) throws IOException {
          out.write(value.getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public boolean hasFixedSize() {
          return false;
        }
      };

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
