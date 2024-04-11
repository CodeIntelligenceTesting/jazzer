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

import com.code_intelligence.jazzer.mutation.utils.AppliesTo;
import com.code_intelligence.jazzer.mutation.utils.PropertyConstraint;
import com.code_intelligence.jazzer.mutation.utils.ValidateContainerDimensions;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * An annotation that applies to {@link String} to <strong>limit the length of the UTF-8
 * encoding</strong> of the string. In practical terms, this means that strings given this
 * annotation will sometimes have a {@link String#length()} of less than {@code min} but will never
 * exceed {@code max}.
 *
 * <p>Due to the fact that our String mutator is backed by the byte array mutator, it's difficult to
 * know how many characters we'll get from the byte array we get from libfuzzer. Rather than reuse
 * {@link WithLength} for strings which may give the impression that {@link String#length()} will
 * return a value between {@code min} and {@code max}, we use this annotation to help make clear
 * that the string consists of between {@code min} and {@code max} UTF-8 bytes, not necessarily
 * (UTF-16) characters.
 */
@Target(TYPE_USE)
@Retention(RUNTIME)
@AppliesTo(String.class)
@ValidateContainerDimensions
@PropertyConstraint
public @interface WithUtf8Length {
  int min() default 0;

  int max() default 1000;

  /**
   * Defines the scope of the annotation. Possible values are defined in {@link
   * com.code_intelligence.jazzer.mutation.utils.PropertyConstraint}.
   */
  String constraint() default PropertyConstraint.DECLARATION;
}
