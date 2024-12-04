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

import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static java.lang.String.format;

import com.code_intelligence.jazzer.mutation.annotation.DoubleInRange;
import com.code_intelligence.jazzer.mutation.annotation.FloatInRange;
import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.mutator.libfuzzer.LibFuzzerMutate;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.DoubleFunction;
import java.util.function.Predicate;
import java.util.stream.DoubleStream;

final class FloatingPointMutatorFactory implements MutatorFactory {
  @SuppressWarnings("unchecked")
  private static final DoubleFunction<Double>[] mathFunctions =
      new DoubleFunction[] {
        Math::acos,
        Math::asin,
        Math::atan,
        Math::cbrt,
        Math::ceil,
        Math::cos,
        Math::cosh,
        Math::exp,
        Math::expm1,
        Math::floor,
        Math::log,
        Math::log10,
        Math::log1p,
        Math::rint,
        Math::sin,
        Math::sinh,
        Math::sqrt,
        Math::tan,
        Math::tanh,
        Math::toDegrees,
        Math::toRadians,
        n -> n * 0.5,
        n -> n * 2.0,
        n -> n * 0.333333333333333,
        n -> n * 3.0
      };

  @Override
  public Optional<SerializingMutator<?>> tryCreate(
      AnnotatedType type, ExtendedMutatorFactory factory) {
    if (!(type.getType() instanceof Class)) {
      return Optional.empty();
    }
    Class<?> clazz = (Class<?>) type.getType();

    if (clazz == float.class || clazz == Float.class) {
      return Optional.of(
          new FloatMutator(type, Float.NEGATIVE_INFINITY, Float.POSITIVE_INFINITY, true));
    } else if (clazz == double.class || clazz == Double.class) {
      return Optional.of(
          new DoubleMutator(type, Double.NEGATIVE_INFINITY, Double.POSITIVE_INFINITY, true));
    } else {
      return Optional.empty();
    }
  }

  static final class FloatMutator extends SerializingMutator<Float> {
    private static final int EXPONENT_INITIAL_BIT = 23;
    private static final int MANTISSA_MASK = 0x7fffff;
    private static final int EXPONENT_MASK = 0xff;
    private static final int MANTISSA_RANDOM_WALK_RANGE = 1000;
    private static final int EXPONENT_RANDOM_WALK_RANGE = Float.MAX_EXPONENT;
    private static final int INVERSE_FREQUENCY_SPECIAL_VALUE = 1000;

    // Visible for testing.
    final float minValue;
    final float maxValue;
    final boolean allowNaN;
    private final float[] specialValues;

    FloatMutator(
        AnnotatedType type,
        float defaultMinValueForType,
        float defaultMaxValueForType,
        boolean defaultAllowNaN) {
      float minValue = defaultMinValueForType;
      float maxValue = defaultMaxValueForType;
      boolean allowNaN = defaultAllowNaN;
      // InRange is not repeatable, so the loop body will apply at most once.
      for (Annotation annotation : type.getAnnotations()) {
        if (annotation instanceof FloatInRange) {
          FloatInRange floatInRange = (FloatInRange) annotation;
          minValue = floatInRange.min();
          maxValue = floatInRange.max();
          allowNaN = floatInRange.allowNaN();
        }
      }

      require(
          minValue <= maxValue,
          format("[%f, %f] is not a valid interval: %s", minValue, maxValue, type));
      require(
          minValue != maxValue,
          format(
              "[%f, %f] can not be mutated, use a constant instead: %s", minValue, maxValue, type));
      this.minValue = minValue;
      this.maxValue = maxValue;
      this.allowNaN = allowNaN;
      this.specialValues = collectSpecialValues(minValue, maxValue);
    }

    private float[] collectSpecialValues(float minValue, float maxValue) {
      // stream of floats
      List<Double> specialValues =
          DoubleStream.of(
                  Float.NEGATIVE_INFINITY,
                  Float.POSITIVE_INFINITY,
                  0.0f,
                  -0.0f,
                  Float.NaN,
                  Float.MAX_VALUE,
                  Float.MIN_VALUE,
                  -Float.MAX_VALUE,
                  -Float.MIN_VALUE,
                  this.minValue,
                  this.maxValue)
              .filter(n -> (n >= minValue && n <= maxValue) || allowNaN && Double.isNaN(n))
              .distinct()
              .sorted()
              .collect(ArrayList::new, ArrayList::add, ArrayList::addAll);

      float[] specialValuesArray = new float[specialValues.size()];
      for (int i = 0; i < specialValues.size(); i++) {
        specialValuesArray[i] = (float) (double) specialValues.get(i);
      }
      return specialValuesArray;
    }

    public float mutateWithLibFuzzer(float value) {
      return LibFuzzerMutate.mutateDefault(value, this, 0);
    }

    @Override
    public Float init(PseudoRandom prng) {
      if (prng.choice()) {
        return specialValues[prng.closedRange(0, specialValues.length - 1)];
      } else {
        return prng.closedRange(minValue, maxValue);
      }
    }

    @Override
    public Float mutate(Float value, PseudoRandom prng) {
      float result;
      // small chance to return a special value
      if (prng.trueInOneOutOf(INVERSE_FREQUENCY_SPECIAL_VALUE)) {
        result = specialValues[prng.closedRange(0, specialValues.length - 1)];
      } else {
        switch (prng.closedRange(0, 5)) {
          case 0:
            result = mutateWithBitFlip(value, prng);
            break;
          case 1:
            result = mutateExponent(value, prng);
            break;
          case 2:
            result = mutateMantissa(value, prng);
            break;
          case 3:
            result = mutateWithMathematicalFn(value, prng);
            break;
          case 4:
            result = mutateWithLibFuzzer(value);
            break;
          case 5: // random in range cannot exceed the given bounds (and cannot be NaN)
            result = prng.closedRange(minValue, maxValue);
            break;
          default:
            throw new IllegalStateException("Unknown mutation case");
        }
      }
      result = forceInRange(result, minValue, maxValue, allowNaN);

      // Repeating values are not allowed.
      if (Float.compare(result, value) == 0) {
        if (Float.isNaN(result)) {
          return prng.closedRange(minValue, maxValue);
        } else { // Change the value to the neighboring float.
          if (result > minValue && result < maxValue) {
            return prng.choice()
                ? Math.nextAfter(result, Float.NEGATIVE_INFINITY)
                : Math.nextAfter(result, Float.POSITIVE_INFINITY);
          } else if (result > minValue) {
            return Math.nextAfter(result, Float.NEGATIVE_INFINITY);
          } else return Math.nextAfter(result, Float.POSITIVE_INFINITY);
        }
      }

      return result;
    }

    static float forceInRange(float value, float minValue, float maxValue, boolean allowNaN) {
      if ((value >= minValue && value <= maxValue) || (Float.isNaN(value) && allowNaN))
        return value;

      // Clamp infinite values
      if (value == Float.POSITIVE_INFINITY) return maxValue;
      if (value == Float.NEGATIVE_INFINITY) return minValue;

      // From here on limits should be finite
      float finiteMax = Math.min(Float.MAX_VALUE, maxValue);
      float finiteMin = Math.max(-Float.MAX_VALUE, minValue);

      // If NaN was allowed, it was handled above. Replace it by the midpoint of the range.
      if (Float.isNaN(value)) return finiteMin * 0.5f + finiteMax * 0.5f;

      float range = finiteMax - finiteMin;
      if (range == 0f) return finiteMin;

      float diff = value - finiteMin;

      if (Float.isFinite(diff) && Float.isFinite(range)) {
        return finiteMin + Math.abs(diff % range);
      }

      // diff, range, or both are infinite: divide both by 2, reduce, and multiply by 2.
      float halfDiff = value * 0.5f - finiteMin * 0.5f;
      return finiteMin + Math.abs(halfDiff % (finiteMax * 0.5f - finiteMin * 0.5f)) * 2.0f;
    }

    public float mutateWithMathematicalFn(float value, PseudoRandom prng) {
      double result = prng.pickIn(mathFunctions).apply(value);
      return (float) result;
    }

    private float mutateWithBitFlip(float value, PseudoRandom prng) {
      int bits = Float.floatToRawIntBits(value);
      int bitToFlip = prng.closedRange(0, 31);
      bits ^= 1L << bitToFlip;
      return Float.intBitsToFloat(bits);
    }

    private float mutateExponent(float value, PseudoRandom prng) {
      int bits = Float.floatToRawIntBits(value);
      int exponent =
          ((bits >> EXPONENT_INITIAL_BIT) & EXPONENT_MASK)
              + prng.closedRange(0, EXPONENT_RANDOM_WALK_RANGE);
      bits =
          (bits & ~(EXPONENT_MASK << EXPONENT_INITIAL_BIT))
              | ((exponent % EXPONENT_MASK) << EXPONENT_INITIAL_BIT);
      return Float.intBitsToFloat(bits);
    }

    private float mutateMantissa(float value, PseudoRandom prng) {
      int bits = Float.floatToRawIntBits(value);

      int mantissa = bits & MANTISSA_MASK;
      switch (prng.closedRange(0, 2)) {
        case 0: // +
          mantissa =
              (mantissa + prng.closedRange(-MANTISSA_RANDOM_WALK_RANGE, MANTISSA_RANDOM_WALK_RANGE))
                  % MANTISSA_MASK;
          break;
        case 1: // *
          mantissa =
              (mantissa * prng.closedRange(-MANTISSA_RANDOM_WALK_RANGE, MANTISSA_RANDOM_WALK_RANGE))
                  % MANTISSA_MASK;
          break;
        case 2: // /
          int divisor = prng.closedRange(2, MANTISSA_RANDOM_WALK_RANGE);
          if (prng.choice()) {
            divisor = -divisor;
          }
          mantissa = (mantissa / divisor);
          break;
        default:
          throw new IllegalStateException("Unknown mutation case for mantissa");
      }
      bits = (bits & ~MANTISSA_MASK) | mantissa;
      return Float.intBitsToFloat(bits);
    }

    @Override
    public Float crossOver(Float value, Float otherValue, PseudoRandom prng) {
      float result;
      switch (prng.closedRange(0, 2)) {
        case 0:
          result = crossOverMean(value, otherValue);
          break;
        case 1:
          result = crossOverExponent(value, otherValue);
          break;
        case 2:
          result = crossOverMantissa(value, otherValue);
          break;
        default:
          throw new IllegalStateException("Unknown mutation case");
      }
      return forceInRange(result, minValue, maxValue, allowNaN);
    }

    private float crossOverMean(float value, float otherValue) {
      return (float) ((((double) value) + ((double) otherValue)) / 2.0);
    }

    private float crossOverExponent(float value, float otherValue) {
      int bits = Float.floatToRawIntBits(value);
      int otherExponent =
          Float.floatToRawIntBits(otherValue) & (EXPONENT_MASK << EXPONENT_INITIAL_BIT);
      int bitsWithOtherExponent = (bits & ~(EXPONENT_MASK << EXPONENT_INITIAL_BIT)) | otherExponent;
      return Float.intBitsToFloat(bitsWithOtherExponent);
    }

    private float crossOverMantissa(float value, float otherValue) {
      int bits = Float.floatToRawIntBits(value);
      int otherMantissa = Float.floatToRawIntBits(otherValue) & MANTISSA_MASK;
      int bitsWithOtherMantissa = (bits & ~MANTISSA_MASK) | otherMantissa;
      return Float.intBitsToFloat(bitsWithOtherMantissa);
    }

    @Override
    public Float read(DataInputStream in) throws IOException {
      return forceInRange(in.readFloat(), minValue, maxValue, allowNaN);
    }

    @Override
    public void write(Float value, DataOutputStream out) throws IOException {
      out.writeFloat(value);
    }

    @Override
    public Float detach(Float value) {
      return value;
    }

    @Override
    public String toDebugString(Predicate<Debuggable> isInCycle) {
      return "Float";
    }

    @Override
    public boolean hasFixedSize() {
      return true;
    }
  }

  static final class DoubleMutator extends SerializingMutator<Double> {
    private static final long MANTISSA_RANDOM_WALK_RANGE = 1000;
    private static final int EXPONENT_RANDOM_WALK_RANGE = Double.MAX_EXPONENT;
    private static final int INVERSE_FREQUENCY_SPECIAL_VALUE = 1000;
    private static final long MANTISSA_MASK = 0xfffffffffffffL;
    private static final long EXPONENT_MASK = 0x7ffL;
    private static final int EXPONENT_INITIAL_BIT = 52;

    // Visible for testing
    final double minValue;
    final double maxValue;
    final boolean allowNaN;
    private final double[] specialValues;

    DoubleMutator(
        AnnotatedType type,
        double defaultMinValueForType,
        double defaultMaxValueForType,
        boolean defaultAllowNaN) {
      double minValue = defaultMinValueForType;
      double maxValue = defaultMaxValueForType;
      boolean allowNaN = defaultAllowNaN;
      // InRange is not repeatable, so the loop body will apply at most once.
      for (Annotation annotation : type.getAnnotations()) {
        if (annotation instanceof DoubleInRange) {
          DoubleInRange doubleInRange = (DoubleInRange) annotation;
          minValue = doubleInRange.min();
          maxValue = doubleInRange.max();
          allowNaN = doubleInRange.allowNaN();
        }
      }

      require(
          !Double.isNaN(minValue) && !Double.isNaN(maxValue),
          format("[%f, %f] is not a valid interval: %s", minValue, maxValue, type));
      require(
          minValue <= maxValue,
          format("[%f, %f] is not a valid interval: %s", minValue, maxValue, type));
      require(
          minValue != maxValue,
          format(
              "[%f, %f] can not be mutated, use a constant instead: %s", minValue, maxValue, type));
      this.minValue = minValue;
      this.maxValue = maxValue;
      this.allowNaN = allowNaN;
      this.specialValues = collectSpecialValues(minValue, maxValue);
    }

    private double[] collectSpecialValues(double minValue, double maxValue) {
      double[] specialValues =
          new double[] {
            Double.NEGATIVE_INFINITY,
            Double.POSITIVE_INFINITY,
            0.0,
            -0.0,
            Double.NaN,
            Double.MAX_VALUE,
            Double.MIN_VALUE,
            -Double.MAX_VALUE,
            -Double.MIN_VALUE,
            this.minValue,
            this.maxValue
          };
      return Arrays.stream(specialValues)
          .boxed()
          .filter(value -> (allowNaN && value.isNaN()) || (value >= minValue && value <= maxValue))
          .distinct()
          .sorted()
          .mapToDouble(Double::doubleValue)
          .toArray();
    }

    public double mutateWithLibFuzzer(double value) {
      return LibFuzzerMutate.mutateDefault(value, this, 0);
    }

    @Override
    public Double init(PseudoRandom prng) {
      if (prng.choice()) {
        return specialValues[prng.closedRange(0, specialValues.length - 1)];
      } else {
        return prng.closedRange(minValue, maxValue);
      }
    }

    @Override
    public Double mutate(Double value, PseudoRandom prng) {
      double result;
      // small chance to return a special value
      if (prng.trueInOneOutOf(INVERSE_FREQUENCY_SPECIAL_VALUE)) {
        result = specialValues[prng.closedRange(0, specialValues.length - 1)];
      } else {
        switch (prng.closedRange(0, 5)) {
          case 0:
            result = mutateWithBitFlip(value, prng);
            break;
          case 1:
            result = mutateExponent(value, prng);
            break;
          case 2:
            result = mutateMantissa(value, prng);
            break;
          case 3:
            result = mutateWithMathematicalFn(value, prng);
            break;
          case 4:
            result = mutateWithLibFuzzer(value);
            break;
          case 5: // random in range cannot exceed the given bounds (and cannot be NaN)
            result = prng.closedRange(minValue, maxValue);
            break;
          default:
            throw new IllegalStateException("Unknown mutation case");
        }
      }
      result = forceInRange(result, minValue, maxValue, allowNaN);

      // Repeating values are not allowed.
      if (Double.compare(result, value) == 0) {
        if (Double.isNaN(result)) {
          return prng.closedRange(minValue, maxValue);
        } else { // Change the value to the neighboring float.
          if (result > minValue && result < maxValue) {
            return prng.choice()
                ? Math.nextAfter(result, Double.NEGATIVE_INFINITY)
                : Math.nextAfter(result, Double.POSITIVE_INFINITY);
          } else if (result > minValue) {
            return Math.nextAfter(result, Double.NEGATIVE_INFINITY);
          } else return Math.nextAfter(result, Double.POSITIVE_INFINITY);
        }
      }

      return result;
    }

    static double forceInRange(double value, double minValue, double maxValue, boolean allowNaN) {
      if ((value >= minValue && value <= maxValue) || (Double.isNaN(value) && allowNaN)) {
        return value;
      }

      // Clamp infinite values
      if (value == Double.POSITIVE_INFINITY) return maxValue;
      if (value == Double.NEGATIVE_INFINITY) return minValue;

      // From here on limits should be finite
      double finiteMax = Math.min(Double.MAX_VALUE, maxValue);
      double finiteMin = Math.max(-Double.MAX_VALUE, minValue);

      // If NaN was allowed, it was handled above.
      // Here we replace NaN by the middle of the clamped finite range.
      if (Double.isNaN(value)) {
        // maxValue or minValue may be infinite, so we need to clamp them.
        return minValue
            + (Math.min(Double.MAX_VALUE, maxValue) * 0.5
                - Math.max(-Double.MAX_VALUE, minValue) * 0.5);
      }

      double range = finiteMax - finiteMin;
      if (range == 0) return finiteMin;

      double diff = value - finiteMin;

      if (Double.isFinite(diff) && Double.isFinite(range)) {
        return finiteMin + Math.abs(diff % range);
      }

      // diff, range, or both are infinite: divide both by 2, reduce, and multiply by 2.
      double halfDiff = value * 0.5 - finiteMin * 0.5;
      return finiteMin + Math.abs(halfDiff % (finiteMax * 0.5 - finiteMin * 0.5)) * 2.0;
    }

    public double mutateWithMathematicalFn(double value, PseudoRandom prng) {
      return prng.pickIn(mathFunctions).apply(value);
    }

    public static double mutateWithBitFlip(double value, PseudoRandom prng) {
      long bits = Double.doubleToRawLongBits(value);
      int bitToFlip = prng.closedRange(0, 63);
      bits ^= 1L << bitToFlip;
      return Double.longBitsToDouble(bits);
    }

    private static double mutateExponent(double value, PseudoRandom prng) {
      long bits = Double.doubleToRawLongBits(value);
      long exponent =
          ((bits >> EXPONENT_INITIAL_BIT) & EXPONENT_MASK)
              + prng.closedRange(0, EXPONENT_RANDOM_WALK_RANGE);
      bits =
          (bits & ~(EXPONENT_MASK << EXPONENT_INITIAL_BIT))
              | ((exponent % EXPONENT_MASK) << EXPONENT_INITIAL_BIT);
      return Double.longBitsToDouble(bits);
    }

    public static double mutateMantissa(double value, PseudoRandom prng) {
      long bits = Double.doubleToRawLongBits(value);
      long mantissa = bits & MANTISSA_MASK;
      switch (prng.closedRange(0, 2)) {
        case 0: // +
          mantissa =
              (mantissa + prng.closedRange(-MANTISSA_RANDOM_WALK_RANGE, MANTISSA_RANDOM_WALK_RANGE))
                  % MANTISSA_MASK;
          break;
        case 1: // *
          mantissa =
              (mantissa * prng.closedRange(-MANTISSA_RANDOM_WALK_RANGE, MANTISSA_RANDOM_WALK_RANGE))
                  % MANTISSA_MASK;
          break;
        case 2: // /
          long divisor = prng.closedRange(2, MANTISSA_RANDOM_WALK_RANGE);
          if (prng.choice()) {
            divisor = -divisor;
          }
          mantissa = (mantissa / divisor);
          break;
        default:
          throw new IllegalStateException("Unknown mutation case for mantissa");
      }
      bits = (bits & ~MANTISSA_MASK) | mantissa;
      return Double.longBitsToDouble(bits);
    }

    @Override
    public Double crossOver(Double value, Double otherValue, PseudoRandom prng) {
      double result;
      switch (prng.closedRange(0, 2)) {
        case 0:
          result = crossOverMean(value, otherValue);
          break;
        case 1:
          result = crossOverExponent(value, otherValue);
          break;
        case 2:
          result = crossOverMantissa(value, otherValue);
          break;
        default:
          throw new IllegalStateException("Unknown mutation case");
      }
      return forceInRange(result, minValue, maxValue, allowNaN);
    }

    private double crossOverMean(double value, double otherValue) {
      return (value * 0.5) + (otherValue * 0.5);
    }

    private double crossOverExponent(double value, double otherValue) {
      long bits = Double.doubleToRawLongBits(value);
      long otherExponent =
          Double.doubleToRawLongBits(otherValue) & (EXPONENT_MASK << EXPONENT_INITIAL_BIT);
      long bitsWithOtherExponent =
          (bits & ~(EXPONENT_MASK << EXPONENT_INITIAL_BIT)) | otherExponent;
      return Double.longBitsToDouble(bitsWithOtherExponent);
    }

    private double crossOverMantissa(double value, double otherValue) {
      long bits = Double.doubleToRawLongBits(value);
      long otherMantissa = Double.doubleToRawLongBits(otherValue) & MANTISSA_MASK;
      long bitsWithOtherMantissa = (bits & ~MANTISSA_MASK) | otherMantissa;
      return Double.longBitsToDouble(bitsWithOtherMantissa);
    }

    @Override
    public boolean hasFixedSize() {
      return true;
    }

    @Override
    public Double read(DataInputStream in) throws IOException {
      return forceInRange(in.readDouble(), minValue, maxValue, allowNaN);
    }

    @Override
    public void write(Double value, DataOutputStream out) throws IOException {
      out.writeDouble(value);
    }

    @Override
    public Double detach(Double value) {
      return value;
    }

    @Override
    public String toDebugString(Predicate<Debuggable> isInCycle) {
      return "Double";
    }
  }
}
