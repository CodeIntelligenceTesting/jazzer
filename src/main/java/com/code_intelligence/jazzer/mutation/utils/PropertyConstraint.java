/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.utils;

import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * The scope of Jazzer annotations can be configured using the constants defined in this
 * meta-annotations. <br>
 * Annotations supporting property constraints need to be marked with this meta-annotation and
 * contain a {@link java.lang.String} property named "constrained", referencing the constants
 * defined in this class.
 */
@Target(ANNOTATION_TYPE)
@Retention(RUNTIME)
public @interface PropertyConstraint {

  /** Annotations restricted with {@code DECLARATION} only apply to the annotated type. */
  String DECLARATION = "JAZZER_PROPERTY_CONSTRAINT_DECLARATION";

  /**
   * Annotations restricted with {@code RECURSIVE} apply to the annotated type, and recursively to
   * all types of components of the annotated one.
   */
  String RECURSIVE = "JAZZER_PROPERTY_CONSTRAINT_RECURSIVE";
}
