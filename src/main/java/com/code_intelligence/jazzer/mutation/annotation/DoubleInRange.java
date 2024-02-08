/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.annotation;

import static java.lang.annotation.ElementType.TYPE_USE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

@Target(TYPE_USE)
@Retention(RUNTIME)
@AppliesTo({double.class, Double.class})
@ValidateMinMax
public @interface DoubleInRange {
  double min() default Double.NEGATIVE_INFINITY;

  double max() default Double.POSITIVE_INFINITY;

  boolean allowNaN() default true;
}
