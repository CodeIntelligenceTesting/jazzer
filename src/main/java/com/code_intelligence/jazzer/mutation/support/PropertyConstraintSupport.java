/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
                    isRecursiveConstraintAnnotation(annotation)
                        && !hasConstraint(target, annotation))
            .toArray(Annotation[]::new);
    return withExtraAnnotations(target, annotationsToPropagate);
  }

  public static boolean isRecursiveConstraintAnnotation(Annotation annotation) {
    return PropertyConstraint.RECURSIVE.equals(constraintFrom(annotation));
  }

  private static boolean isConstraintAnnotation(Annotation annotation) {
    return annotation.annotationType().getAnnotation(PropertyConstraint.class) != null;
  }

  private static String constraintFrom(Annotation constraint) {
    if (!isConstraintAnnotation(constraint)) {
      return null;
    }
    try {
      return (String)
          constraint.annotationType().getDeclaredMethod("constraint").invoke(constraint);
    } catch (Exception ignored) {
      return "";
    }
  }

  private static boolean hasConstraint(AnnotatedType target, Annotation constraint) {
    return target.getAnnotation(constraint.annotationType()) != null;
  }

  private PropertyConstraintSupport() {}
}
