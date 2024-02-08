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

/**
 * Meta-annotation intended to be used internally by Jazzer for container annotations with min and
 * max fields. Annotations annotated with @ValidateContainerDimensions will be validated to ensure
 * that min and max are both >= 0, and that min <= max.
 */
@Target(ANNOTATION_TYPE)
@Retention(RUNTIME)
public @interface ValidateContainerDimensions {}
