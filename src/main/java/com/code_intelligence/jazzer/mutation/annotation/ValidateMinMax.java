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
 * Meta-annotation intended to be used internally by Jazzer for annotations that have min and max
 * fields. For all such annotations, Jazzer will assert that min <= max.
 */
@Target(ANNOTATION_TYPE)
@Retention(RUNTIME)
public @interface ValidateMinMax {}
