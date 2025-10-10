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

package com.code_intelligence.jazzer.mutation.support;

import com.code_intelligence.jazzer.mutation.annotation.*;
import com.code_intelligence.jazzer.mutation.annotation.Negative;
import com.code_intelligence.jazzer.mutation.annotation.NonNegative;
import com.code_intelligence.jazzer.mutation.annotation.NonPositive;
import com.code_intelligence.jazzer.mutation.annotation.Positive;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedType;

/**
 * Utilities to derive range constraints from annotations.
 *
 * <p>Centralizes mapping of convenience property annotations (e.g. @Positive) to concrete range
 * values.
 */
public final class RangeSupport {
  private RangeSupport() {}

  public static final class LongRange {
    public final long min;
    public final long max;

    public LongRange(long min, long max) {
      this.min = min;
      this.max = max;
    }
  }

  public static final class FloatRange {
    public final float min;
    public final float max;
    public final boolean allowNaN;

    public FloatRange(float min, float max, boolean allowNaN) {
      this.min = min;
      this.max = max;
      this.allowNaN = allowNaN;
    }
  }

  public static final class DoubleRange {
    public final double min;
    public final double max;
    public final boolean allowNaN;

    public DoubleRange(double min, double max, boolean allowNaN) {
      this.min = min;
      this.max = max;
      this.allowNaN = allowNaN;
    }
  }

  public static LongRange resolveIntegralRange(
      AnnotatedType type, long defaultMin, long defaultMax) {
    long minValue = defaultMin;
    long maxValue = defaultMax;
    for (Annotation annotation : type.getAnnotations()) {
      if (annotation instanceof InRange) {
        InRange inRange = (InRange) annotation;
        minValue = Math.max(inRange.min(), defaultMin);
        maxValue = Math.min(inRange.max(), defaultMax);
      } else if (annotation instanceof Positive) {
        minValue = 1;
        maxValue = defaultMax;
      } else if (annotation instanceof Negative) {
        minValue = defaultMin;
        maxValue = -1;
      } else if (annotation instanceof NonNegative) {
        minValue = 0;
        maxValue = defaultMax;
      } else if (annotation instanceof NonPositive) {
        minValue = defaultMin;
        maxValue = 0;
      }
    }
    return new LongRange(minValue, maxValue);
  }

  public static FloatRange resolveFloatRange(
      AnnotatedType type, float defaultMin, float defaultMax, boolean defaultAllowNaN) {
    float minValue = defaultMin;
    float maxValue = defaultMax;
    boolean allowNaN = defaultAllowNaN;
    for (Annotation annotation : type.getAnnotations()) {
      if (annotation instanceof FloatInRange) {
        FloatInRange floatInRange = (FloatInRange) annotation;
        minValue = floatInRange.min();
        maxValue = floatInRange.max();
        allowNaN = floatInRange.allowNaN();
      } else if (annotation instanceof Positive) {
        minValue = Float.MIN_VALUE;
        maxValue = defaultMax;
        allowNaN = false;
      } else if (annotation instanceof Negative) {
        minValue = defaultMin;
        maxValue = -Float.MIN_VALUE;
        allowNaN = false;
      } else if (annotation instanceof NonNegative) {
        minValue = 0.0f;
        maxValue = defaultMax;
        allowNaN = false;
      } else if (annotation instanceof NonPositive) {
        minValue = defaultMin;
        maxValue = 0.0f;
        allowNaN = false;
      } else if (annotation instanceof Finite) {
        minValue = -Float.MAX_VALUE;
        maxValue = Float.MAX_VALUE;
        allowNaN = false;
      }
    }
    return new FloatRange(minValue, maxValue, allowNaN);
  }

  public static DoubleRange resolveDoubleRange(
      AnnotatedType type, double defaultMin, double defaultMax, boolean defaultAllowNaN) {
    double minValue = defaultMin;
    double maxValue = defaultMax;
    boolean allowNaN = defaultAllowNaN;
    for (Annotation annotation : type.getAnnotations()) {
      if (annotation instanceof DoubleInRange) {
        DoubleInRange doubleInRange = (DoubleInRange) annotation;
        minValue = doubleInRange.min();
        maxValue = doubleInRange.max();
        allowNaN = doubleInRange.allowNaN();
      } else if (annotation instanceof Positive) {
        minValue = Double.MIN_VALUE;
        maxValue = defaultMax;
        allowNaN = false;
      } else if (annotation instanceof Negative) {
        minValue = defaultMin;
        maxValue = -Double.MIN_VALUE;
        allowNaN = false;
      } else if (annotation instanceof NonNegative) {
        minValue = 0.0;
        maxValue = defaultMax;
        allowNaN = false;
      } else if (annotation instanceof NonPositive) {
        minValue = defaultMin;
        maxValue = 0.0;
        allowNaN = false;
      } else if (annotation instanceof Finite) {
        minValue = -Double.MAX_VALUE;
        maxValue = Double.MAX_VALUE;
        allowNaN = false;
      }
    }
    return new DoubleRange(minValue, maxValue, allowNaN);
  }
}
