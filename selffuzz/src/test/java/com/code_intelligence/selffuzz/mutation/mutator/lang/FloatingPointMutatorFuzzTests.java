/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.selffuzz.mutation.mutator.lang;

import static com.code_intelligence.selffuzz.Helpers.assertMutator;
import static com.code_intelligence.selffuzz.jazzer.mutation.support.TypeSupport.withExtraAnnotations;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.selffuzz.jazzer.mutation.annotation.DoubleInRange;
import com.code_intelligence.selffuzz.jazzer.mutation.annotation.FloatInRange;
import com.code_intelligence.selffuzz.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.selffuzz.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.selffuzz.jazzer.mutation.mutator.lang.LangMutators;
import com.code_intelligence.selffuzz.jazzer.mutation.support.TypeHolder;
import java.io.IOException;
import java.lang.annotation.Annotation;

@SuppressWarnings("unchecked")
class FloatingPointMutatorFuzzTests {
  @FuzzTest(maxDuration = "10m")
  public void doubleMutatorTest(double min, double max, long seed, byte @NotNull [] data)
      throws IOException {
    DoubleInRange range = rndDoubleInRange(min, max);
    assumeTrue(range != null);
    SerializingMutator<Double> mutator =
        (SerializingMutator<Double>)
            LangMutators.newFactory()
                .createOrThrow(
                    withExtraAnnotations(
                        new TypeHolder<@NotNull Double>() {}.annotatedType(), range));
    assertMutator(mutator, data, seed);
  }

  @FuzzTest(maxDuration = "10m")
  public void floatMutatorTest(float min, float max, long seed, byte @NotNull [] data)
      throws IOException {
    FloatInRange range = rndFloatInRange(min, max);
    assumeTrue(range != null);
    SerializingMutator<Float> mutator =
        (SerializingMutator<Float>)
            LangMutators.newFactory()
                .createOrThrow(
                    withExtraAnnotations(
                        new TypeHolder<@NotNull Float>() {}.annotatedType(), range));
    assertMutator(mutator, data, seed);
  }

  private static DoubleInRange rndDoubleInRange(double min, double max) {
    // Use == instead of compare to handle -0.0 == 0.0.
    if (min == max || Double.isNaN(min) || Double.isNaN(max)) {
      return null;
    }
    double actualMin = Math.min(min, max);
    double actualMax = Math.max(min, max);
    return new DoubleInRange() {
      @Override
      public double min() {
        return actualMin;
      }

      @Override
      public double max() {
        return actualMax;
      }

      @Override
      public boolean allowNaN() {
        return true;
      }

      @Override
      public Class<? extends Annotation> annotationType() {
        return DoubleInRange.class;
      }

      @Override
      public boolean equals(Object o) {
        if (!(o instanceof DoubleInRange)) {
          return false;
        }
        DoubleInRange other = (DoubleInRange) o;
        return this.min() == other.min()
            && this.max() == other.max()
            && this.allowNaN() == other.allowNaN();
      }

      @Override
      public int hashCode() {
        int hash = 0;
        hash += ("min".hashCode() * 127) ^ Double.valueOf(this.min()).hashCode();
        hash += ("max".hashCode() * 127) ^ Double.valueOf(this.max()).hashCode();
        hash += ("allowNaN".hashCode() * 127) ^ Boolean.valueOf(this.allowNaN()).hashCode();
        return hash;
      }
    };
  }

  private static FloatInRange rndFloatInRange(float min, float max) {
    // Use == instead of compare to handle -0.0 == 0.0.
    if (min == max || Float.isNaN(min) || Float.isNaN(max)) {
      return null;
    }
    float actualMin = Math.min(min, max);
    float actualMax = Math.max(min, max);
    return new FloatInRange() {
      @Override
      public float min() {
        return actualMin;
      }

      @Override
      public float max() {
        return actualMax;
      }

      @Override
      public boolean allowNaN() {
        return true;
      }

      @Override
      public Class<? extends Annotation> annotationType() {
        return FloatInRange.class;
      }

      @Override
      public boolean equals(Object o) {
        if (!(o instanceof FloatInRange)) {
          return false;
        }
        FloatInRange other = (FloatInRange) o;
        return this.min() == other.min()
            && this.max() == other.max()
            && this.allowNaN() == other.allowNaN();
      }

      @Override
      public int hashCode() {
        int hash = 0;
        hash += ("min".hashCode() * 127) ^ Float.valueOf(this.min()).hashCode();
        hash += ("max".hashCode() * 127) ^ Float.valueOf(this.max()).hashCode();
        hash += ("allowNaN".hashCode() * 127) ^ Boolean.valueOf(this.allowNaN()).hashCode();
        return hash;
      }
    };
  }
}
