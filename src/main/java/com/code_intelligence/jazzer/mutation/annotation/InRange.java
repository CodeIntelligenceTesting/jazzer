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
@AppliesTo({
  byte.class,
  Byte.class,
  short.class,
  Short.class,
  int.class,
  Integer.class,
  long.class,
  Long.class
})
@ValidateMinMax
public @interface InRange {
  long min() default Long.MIN_VALUE;

  long max() default Long.MAX_VALUE;
}
