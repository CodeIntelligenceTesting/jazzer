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

package com.code_intelligence.jazzer.mutation.mutator.lang;

import static com.code_intelligence.jazzer.mutation.mutator.lang.FloatingPointMutatorFactory.DoubleMutator;
import static com.code_intelligence.jazzer.mutation.mutator.lang.FloatingPointMutatorFactory.FloatMutator;
import static com.code_intelligence.jazzer.mutation.mutator.lang.IntegralMutatorFactory.AbstractIntegralMutator.forceInRange;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.findFirstParentIfClass;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.forwardAnnotations;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.withLength;

import com.code_intelligence.jazzer.mutation.annotation.DoubleInRange;
import com.code_intelligence.jazzer.mutation.annotation.FloatInRange;
import com.code_intelligence.jazzer.mutation.annotation.InRange;
import com.code_intelligence.jazzer.mutation.annotation.WithLength;
import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.mutator.libfuzzer.LibFuzzerMutatorFactory;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.AnnotatedArrayType;
import java.lang.reflect.AnnotatedType;
import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;

final class PrimitiveArrayMutatorFactory implements MutatorFactory {

  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {

    Optional<Class<?>> clazz =
        findFirstParentIfClass(
            type,
            byte[].class,
            int[].class,
            long[].class,
            short[].class,
            char[].class,
            float[].class,
            double[].class,
            boolean[].class);
    return clazz.map(aClass -> new PrimitiveArrayMutator<>(type));
  }

  // public for testing
  public static final class PrimitiveArrayMutator<T> extends SerializingMutator<T> {
    private static final int DEFAULT_MIN_LENGTH = 0;
    private static final int DEFAULT_MAX_LENGTH = 1000;
    private long minRange;
    private long maxRange;
    private boolean allowNaN;
    private float minFloatRange;
    private float maxFloatRange;
    private double minDoubleRange;
    private double maxDoubleRange;
    private final AnnotatedType elementType;
    private final SerializingMutator<byte[]> innerMutator;
    private final Function<byte[], T> toPrimitive;
    private final Function<T, byte[]> toBytes;

    @SuppressWarnings("unchecked")
    public PrimitiveArrayMutator(AnnotatedType type) {
      elementType = ((AnnotatedArrayType) type).getAnnotatedGenericComponentType();
      extractRange(elementType);
      AnnotatedType innerByteArray =
          forwardAnnotations(
              type, convertWithLength(type, new TypeHolder<byte[]>() {}.annotatedType()));
      innerMutator =
          (SerializingMutator<byte[]>) LibFuzzerMutatorFactory.tryCreate(innerByteArray).get();
      toPrimitive = (Function<byte[], T>) makeBytesToPrimitiveArrayConverter(elementType);
      toBytes = (Function<T, byte[]>) makePrimitiveArrayToBytesConverter(elementType);
    }

    @Override
    public boolean hasFixedSize() {
      return false;
    }

    @Override
    public String toDebugString(Predicate<Debuggable> isInCycle) {
      return elementType.getType() + "[]";
    }

    @Override
    public T detach(T value) {
      // The value is detached already because it was copied from libFuzzer's byte array
      return value;
    }

    @Override
    public T read(DataInputStream in) throws IOException {
      return (T) toPrimitive.apply(innerMutator.read(in));
    }

    @Override
    public void write(T value, DataOutputStream out) throws IOException {
      innerMutator.write(toBytes.apply(value), out);
    }

    @Override
    public T init(PseudoRandom prng) {
      return (T) toPrimitive.apply(innerMutator.init(prng));
    }

    @Override
    public T mutate(T value, PseudoRandom prng) {
      return (T) toPrimitive.apply(innerMutator.mutate(toBytes.apply(value), prng));
    }

    @Override
    public T crossOver(T value, T otherValue, PseudoRandom prng) {
      return (T)
          toPrimitive.apply(
              innerMutator.crossOver(toBytes.apply(value), toBytes.apply(otherValue), prng));
    }

    private void extractRange(AnnotatedType type) {
      Optional<InRange> inRange = Optional.ofNullable(type.getAnnotation(InRange.class));
      Optional<FloatInRange> inRangeFloat =
          Optional.ofNullable(type.getAnnotation(FloatInRange.class));
      Optional<DoubleInRange> inRangeDouble =
          Optional.ofNullable(type.getAnnotation(DoubleInRange.class));

      switch (type.getType().getTypeName()) {
        case "int":
          minRange = inRange.map(InRange::min).orElse((long) Integer.MIN_VALUE);
          maxRange = inRange.map(InRange::max).orElse((long) Integer.MAX_VALUE);
          break;
        case "long":
          minRange = inRange.map(InRange::min).orElse(Long.MIN_VALUE);
          maxRange = inRange.map(InRange::max).orElse(Long.MAX_VALUE);
          break;
        case "short":
          minRange = inRange.map(InRange::min).orElse((long) Short.MIN_VALUE);
          maxRange = inRange.map(InRange::max).orElse((long) Short.MAX_VALUE);
          break;
        case "char":
          minRange = inRange.map(InRange::min).orElse((long) Character.MIN_VALUE);
          maxRange = inRange.map(InRange::max).orElse((long) Character.MAX_VALUE);
          break;
        case "float":
          minFloatRange = inRangeFloat.map(FloatInRange::min).orElse(Float.NEGATIVE_INFINITY);
          maxFloatRange = inRangeFloat.map(FloatInRange::max).orElse(Float.POSITIVE_INFINITY);
          allowNaN = inRangeFloat.map(FloatInRange::allowNaN).orElse(false);
          break;
        case "double":
          minDoubleRange = inRangeDouble.map(DoubleInRange::min).orElse(Double.NEGATIVE_INFINITY);
          maxDoubleRange = inRangeDouble.map(DoubleInRange::max).orElse(Double.POSITIVE_INFINITY);
          allowNaN = inRangeDouble.map(DoubleInRange::allowNaN).orElse(false);
          break;
        case "boolean":
          minRange = inRange.map(InRange::min).orElse(0L);
          maxRange = inRange.map(InRange::max).orElse(1L);
          break;
        case "byte":
          minRange = inRange.map(InRange::min).orElse((long) Byte.MIN_VALUE);
          maxRange = inRange.map(InRange::max).orElse((long) Byte.MAX_VALUE);
          break;
        default:
          throw new IllegalStateException("Unexpected type: " + type);
      }
    }

    private static AnnotatedType convertWithLength(AnnotatedType type, AnnotatedType newType) {
      AnnotatedType elementType = ((AnnotatedArrayType) type).getAnnotatedGenericComponentType();
      Optional<WithLength> withLength = Optional.ofNullable(type.getAnnotation(WithLength.class));
      int minLength = withLength.map(WithLength::min).orElse(DEFAULT_MIN_LENGTH);
      int maxLength = withLength.map(WithLength::max).orElse(DEFAULT_MAX_LENGTH);
      switch (elementType.getType().getTypeName()) {
        case "int":
        case "float":
          return withLength(newType, minLength * 4, maxLength * 4);
        case "long":
        case "double":
          return withLength(newType, minLength * 8, maxLength * 8);
        case "short":
        case "char":
          return withLength(newType, minLength * 2, maxLength * 2);
        case "boolean":
        case "byte":
          return withLength(newType, minLength, maxLength);
        default:
          throw new IllegalStateException("Unexpected value: " + elementType);
      }
    }

    private Function<byte[], ?> makeBytesToPrimitiveArrayConverter(AnnotatedType type) {
      switch (type.getType().getTypeName()) {
        case "int":
          return getIntegerPrimitiveArray(minRange, maxRange);
        case "long":
          return getLongPrimitiveArray(minRange, maxRange);
        case "short":
          return getShortPrimitiveArray(minRange, maxRange);
        case "char":
          return getCharPrimitiveArray(minRange, maxRange);
        case "float":
          return getFloatPrimitiveArray(minFloatRange, maxFloatRange, allowNaN);
        case "double":
          return getDoublePrimitiveArray(minDoubleRange, maxDoubleRange, allowNaN);
        case "boolean":
          return getBooleanPrimitiveArray(minRange, maxRange);
        case "byte":
          return getBytePrimitiveArray(minRange, maxRange);
        default:
          throw new IllegalStateException("Unexpected value: " + type);
      }
    }

    public static Function<?, byte[]> makePrimitiveArrayToBytesConverter(AnnotatedType type) {
      switch (type.getType().getTypeName()) {
        case "int":
          return (int[] array) -> {
            if (array == null) return null;
            ByteBuffer buffer = ByteBuffer.allocate(array.length * 4);
            buffer.asIntBuffer().put(array);
            return buffer.array();
          };
        case "long":
          return (long[] array) -> {
            if (array == null) return null;
            ByteBuffer buffer = ByteBuffer.allocate(array.length * 8);
            buffer.asLongBuffer().put(array);
            return buffer.array();
          };
        case "short":
          return (short[] array) -> {
            if (array == null) return null;
            ByteBuffer buffer = ByteBuffer.allocate(array.length * 2);
            buffer.asShortBuffer().put(array);
            return buffer.array();
          };
        case "char":
          return (char[] array) -> {
            if (array == null) return null;
            ByteBuffer buffer = ByteBuffer.allocate(array.length * 2);
            buffer.asCharBuffer().put(array);
            return buffer.array();
          };
        case "float":
          return (float[] array) -> {
            if (array == null) return null;
            ByteBuffer buffer = ByteBuffer.allocate(array.length * 4);
            buffer.asFloatBuffer().put(array);
            return buffer.array();
          };
        case "double":
          return (double[] array) -> {
            if (array == null) return null;
            ByteBuffer buffer = ByteBuffer.allocate(array.length * 8);
            buffer.asDoubleBuffer().put(array);
            return buffer.array();
          };
        case "boolean":
          return (boolean[] array) -> {
            if (array == null) return null;
            byte[] buffer = new byte[array.length];
            for (int i = 0; i < array.length; i++) {
              buffer[i] = (byte) (array[i] ? 1 : 0);
            }
            return buffer;
          };
        case "byte":
          return (byte[] array) -> array;
        default:
          throw new IllegalStateException("Unexpected value: " + type);
      }
    }

    public static Function<byte[], int[]> getIntegerPrimitiveArray(long minRange, long maxRange) {
      int nBytes = 4;
      return (byte[] byteArray) -> {
        if (byteArray == null) return null;
        int extraBytes = byteArray.length % nBytes;
        int[] result = new int[byteArray.length / nBytes + (extraBytes > 0 ? 1 : 0)];
        ByteBuffer buffer = ByteBuffer.wrap(byteArray);
        for (int i = 0; i < byteArray.length / nBytes; i++) {
          result[i] = (int) forceInRange(buffer.getInt(), minRange, maxRange);
        }
        if (extraBytes > 0) {
          int i = 0;
          while (buffer.hasRemaining()) {
            result[result.length - 1] |= (buffer.get() & 0xff) << (8 * (extraBytes - 1 - i));
            i++;
          }
          result[result.length - 1] =
              (int) forceInRange(result[result.length - 1], minRange, maxRange);
        }
        return result;
      };
    }

    public static Function<byte[], long[]> getLongPrimitiveArray(long minRange, long maxRange) {
      int nBytes = 8;
      return (byte[] byteArray) -> {
        if (byteArray == null) return null;
        long extraBytes = byteArray.length % nBytes;
        long[] result = new long[byteArray.length / nBytes + (extraBytes > 0 ? 1 : 0)];
        ByteBuffer buffer = ByteBuffer.wrap(byteArray);
        for (int i = 0; i < byteArray.length / nBytes; i++) {
          result[i] = forceInRange(buffer.getLong(), minRange, maxRange);
        }
        if (extraBytes > 0) {
          int i = 0;
          while (buffer.hasRemaining()) {
            result[result.length - 1] |= (long) (buffer.get() & 0xff) << (8 * (extraBytes - 1 - i));
            i++;
          }
          result[result.length - 1] = forceInRange(result[result.length - 1], minRange, maxRange);
        }
        return result;
      };
    }

    public static Function<byte[], short[]> getShortPrimitiveArray(long minRange, long maxRange) {
      int nBytes = 2;
      return (byte[] byteArray) -> {
        if (byteArray == null) return null;
        short extraBytes = (short) (byteArray.length % nBytes);
        short[] result = new short[byteArray.length / nBytes + (extraBytes > 0 ? 1 : 0)];
        ByteBuffer buffer = ByteBuffer.wrap(byteArray);
        for (int i = 0; i < byteArray.length / nBytes; i++) {
          result[i] = (short) forceInRange(buffer.getShort(), minRange, maxRange);
        }
        if (extraBytes > 0) {
          int i = 0;
          while (buffer.hasRemaining()) {
            result[result.length - 1] |=
                (short) ((buffer.get() & 0xff) << (8 * (extraBytes - 1 - i)));
            i++;
          }
          result[result.length - 1] =
              (short) forceInRange(result[result.length - 1], minRange, maxRange);
        }
        return result;
      };
    }

    public static Function<byte[], char[]> getCharPrimitiveArray(long minRange, long maxRange) {
      int nBytes = 2;
      return (byte[] byteArray) -> {
        if (byteArray == null) return null;
        char extraBytes = (char) (byteArray.length % nBytes);
        char[] result = new char[byteArray.length / nBytes + (extraBytes > 0 ? 1 : 0)];
        ByteBuffer buffer = ByteBuffer.wrap(byteArray);
        for (int i = 0; i < byteArray.length / nBytes; i++) {
          result[i] = (char) forceInRange(buffer.getChar(), minRange, maxRange);
        }
        if (extraBytes > 0) {
          int i = 0;
          while (buffer.hasRemaining()) {
            result[result.length - 1] |=
                (char) ((buffer.get() & 0xff) << (8 * (extraBytes - 1 - i)));
            i++;
          }
          result[result.length - 1] =
              (char) forceInRange(result[result.length - 1], minRange, maxRange);
        }
        return result;
      };
    }

    public static Function<byte[], float[]> getFloatPrimitiveArray(
        float minFloatRange, float maxFloatRange, boolean allowNaN) {
      int nBytes = 4;
      return (byte[] byteArray) -> {
        if (byteArray == null) return null;
        int extraBytes = byteArray.length % nBytes;
        float[] result = new float[byteArray.length / nBytes + (extraBytes > 0 ? 1 : 0)];
        ByteBuffer buffer = ByteBuffer.wrap(byteArray);
        for (int i = 0; i < byteArray.length / nBytes; i++) {
          result[i] =
              FloatMutator.forceInRange(buffer.getFloat(), minFloatRange, maxFloatRange, allowNaN);
        }
        if (extraBytes > 0) {
          int i = 0;
          int lastNumber = 0;
          while (buffer.hasRemaining()) {
            lastNumber |= (buffer.get() & 0xff) << (8 * (extraBytes - 1 - i));
            i++;
          }

          result[result.length - 1] =
              FloatMutator.forceInRange(
                  Float.intBitsToFloat(lastNumber), minFloatRange, maxFloatRange, allowNaN);
        }
        return result;
      };
    }

    public static Function<byte[], double[]> getDoublePrimitiveArray(
        double minDoubleRange, double maxDoubleRange, boolean allowNaN) {
      int nBytes = 8;
      return (byte[] byteArray) -> {
        if (byteArray == null) return null;
        int extraBytes = byteArray.length % nBytes;
        double[] result = new double[byteArray.length / nBytes + (extraBytes > 0 ? 1 : 0)];
        ByteBuffer buffer = ByteBuffer.wrap(byteArray);
        for (int i = 0; i < byteArray.length / nBytes; i++) {
          result[i] =
              DoubleMutator.forceInRange(
                  buffer.getDouble(), minDoubleRange, maxDoubleRange, allowNaN);
        }
        if (extraBytes > 0) {
          int i = 0;
          long lastNumber = 0;
          while (buffer.hasRemaining()) {
            lastNumber |= ((long) (buffer.get() & 0xff)) << (8 * (extraBytes - 1 - i));
            i++;
          }
          result[result.length - 1] =
              DoubleMutator.forceInRange(
                  Double.longBitsToDouble(lastNumber), minDoubleRange, maxDoubleRange, allowNaN);
        }
        return result;
      };
    }

    public static Function<byte[], boolean[]> getBooleanPrimitiveArray(
        long minRange, long maxRange) {
      return (byte[] byteArray) -> {
        if (byteArray == null) return null;
        boolean[] result = new boolean[byteArray.length];
        for (int i = 0; i < byteArray.length; i++) {
          result[i] = forceInRange(byteArray[i], minRange, maxRange) == 1;
        }
        return result;
      };
    }

    public static Function<byte[], byte[]> getBytePrimitiveArray(long minRange, long maxRange) {
      return (byte[] byteArray) -> {
        if (byteArray == null) return null;
        byte[] result = new byte[byteArray.length];
        for (int i = 0; i < byteArray.length; i++) {
          result[i] = (byte) forceInRange(byteArray[i], minRange, maxRange);
        }
        return result;
      };
    }
  }
}
