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
@AppliesTo({float.class, Float.class})
public @interface FloatInRange {
  float min() default Float.NEGATIVE_INFINITY;

  float max() default Float.POSITIVE_INFINITY;

  boolean allowNaN() default true;
}
