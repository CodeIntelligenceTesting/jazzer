/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.annotation;

import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/** A meta-annotation that limits the concrete types an annotation for type usages applies to. */
@Target(ANNOTATION_TYPE)
@Retention(RUNTIME)
public @interface AppliesTo {
  /** The meta-annotated annotation can be applied to these classes. */
  Class<?>[] value() default {};

  /** The meta-annotated annotation can be applied to subclasses of these classes. */
  Class<?>[] subClassesOf() default {};
}
