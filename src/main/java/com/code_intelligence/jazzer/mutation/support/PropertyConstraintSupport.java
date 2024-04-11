/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.support;

import static com.code_intelligence.jazzer.mutation.support.TypeSupport.withExtraAnnotations;
import static java.util.Arrays.stream;

import com.code_intelligence.jazzer.mutation.utils.PropertyConstraint;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedType;

public final class PropertyConstraintSupport {

  public static AnnotatedType propagatePropertyConstraints(
      AnnotatedType src, AnnotatedType target) {
    Annotation[] annotationsToPropagate =
        stream(src.getAnnotations())
            .filter(
                annotation ->
                    isConstraintAnnotation(annotation)
                        && PropertyConstraint.RECURSIVE.equals(constraintFrom(annotation))
                        && !hasConstraint(target, annotation))
            .toArray(Annotation[]::new);
    return withExtraAnnotations(target, annotationsToPropagate);
  }

  private static boolean isConstraintAnnotation(Annotation annotation) {
    return annotation.annotationType().getAnnotation(PropertyConstraint.class) != null;
  }

  private static boolean hasConstraint(AnnotatedType target, Annotation constraint) {
    return target.getAnnotation(constraint.annotationType()) != null;
  }

  private static String constraintFrom(Annotation constraint) {
    try {
      return (String)
          constraint.annotationType().getDeclaredMethod("constraint").invoke(constraint);
    } catch (Exception ignored) {
      return "";
    }
  }
}
