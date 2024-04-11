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
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * An annotation that applies to {@link String} and <strong>limits the character set</strong> of the
 * annotated type to valid URL segment characters, as described in <a
 * href="https://www.ietf.org/rfc/rfc3986.txt">RFC 3986, appendix A</a>. </br> Can be combined with
 * {@link WithUtf8Length} to limit the length of the generated string.
 */
@Target(TYPE_USE)
@Retention(RUNTIME)
@AppliesTo(String.class)
@PropertyConstraint
public @interface UrlSegment {

  /**
   * Defines the scope of the annotation. Possible values are defined in {@link
   * com.code_intelligence.jazzer.mutation.utils.PropertyConstraint}.
   */
  String constraint() default PropertyConstraint.DECLARATION;
}
