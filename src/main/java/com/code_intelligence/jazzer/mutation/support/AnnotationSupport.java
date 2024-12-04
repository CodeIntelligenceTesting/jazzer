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

import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static com.code_intelligence.jazzer.mutation.support.PropertyConstraintSupport.isRecursiveConstraintAnnotation;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.visitAnnotatedType;
import static java.lang.String.format;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.joining;

import com.code_intelligence.jazzer.mutation.utils.AppliesTo;
import com.code_intelligence.jazzer.mutation.utils.ValidateContainerDimensions;
import com.code_intelligence.jazzer.mutation.utils.ValidateMinMax;
import com.code_intelligence.jazzer.utils.Log;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.InvocationTargetException;

/**
 * Throws an exception if any annotation on {@code type} violates the restrictions of its {@link
 * AppliesTo} meta-annotation, or if any other annotation has conflicting values (e.g. min > max).
 */
public class AnnotationSupport {
  public static void validateAnnotationUsage(AnnotatedType type) {
    visitAnnotatedType(
        type,
        (clazz, annotations) -> {
          for (Annotation annotation : annotations) {
            ensureDeepAppliesTo(annotation, clazz);
            ensureMinLessThanOrEqualsMax(annotation);
            validateContainerDimensions(annotation);
          }
        });
  }

  private static void ensureDeepAppliesTo(Annotation annotation, Class<?> clazz) {
    AppliesTo appliesTo = annotation.annotationType().getAnnotation(AppliesTo.class);
    if (appliesTo == null) {
      return;
    }
    if (isRecursiveConstraintAnnotation(annotation)) {
      return;
    }

    for (Class<?> allowedClass : appliesTo.value()) {
      if (allowedClass == clazz) {
        return;
      }
    }
    for (Class<?> allowedSuperClass : appliesTo.subClassesOf()) {
      if (allowedSuperClass.isAssignableFrom(clazz)) {
        return;
      }
    }

    String helpText = "";
    if (appliesTo.value().length != 0) {
      helpText = stream(appliesTo.value()).map(Class::getName).collect(joining(", "));
    }
    if (appliesTo.subClassesOf().length != 0) {
      if (!helpText.isEmpty()) {
        helpText += "as well as ";
      }
      helpText += "subclasses of ";
      helpText += stream(appliesTo.subClassesOf()).map(Class::getName).collect(joining(", "));
    }
    // Use the simple name as our annotations live in a single package.
    throw new IllegalArgumentException(
        format(
            "@%s does not apply to %s, only applies to %s",
            annotation.annotationType().getSimpleName(), clazz.getName(), helpText));
  }

  private static void ensureMinLessThanOrEqualsMax(Annotation annotation) {
    String name = annotation.annotationType().getSimpleName();

    if (annotation.annotationType().getAnnotation(ValidateMinMax.class) != null) {
      try {
        Class<?> returnType = annotation.annotationType().getMethod("min").getReturnType();
        Object min = annotation.annotationType().getMethod("min").invoke(annotation);
        Object max = annotation.annotationType().getMethod("max").invoke(annotation);
        if (returnType == int.class || returnType == Integer.class) {
          require(
              (Integer) min <= (Integer) max,
              format(
                  "@%s(min=%d, max=%d): min must be less than or equal to max.",
                  name, (Integer) min, (Integer) max));
        } else if (returnType == long.class || returnType == Long.class) {
          require(
              (Long) min <= (Long) max,
              format(
                  "@%s(min=%d, max=%d): min must be less than or equal to max.",
                  name, (Long) min, (Long) max));
        } else if (returnType == float.class || returnType == Float.class) {
          require(
              (Float) min <= (Float) max,
              format(
                  "@%s(min=%f, max=%f): min must be less than or equal to max.",
                  name, (Float) min, (Float) max));
        } else if (returnType == double.class || returnType == Double.class) {
          require(
              (Double) min <= (Double) max,
              format(
                  "@%s(min=%f, max=%f): min must be less than or equal to max.",
                  name, (Double) min, (Double) max));
        } else {
          throw new IllegalArgumentException("Unsupported type for min/max: " + returnType);
        }
      } catch (NoSuchMethodException e) {
        throw new RuntimeException("Failed to access min/max fields of annotation", e);
      } catch (InvocationTargetException | IllegalAccessException e) {
        throw new RuntimeException(e);
      }
    }
  }

  private static void validateContainerDimensions(Annotation annotation) {
    if (annotation.annotationType().getAnnotation(ValidateContainerDimensions.class) != null) {
      try {
        String name = annotation.annotationType().getSimpleName();
        Integer min = (Integer) annotation.annotationType().getMethod("min").invoke(annotation);
        Integer max = (Integer) annotation.annotationType().getMethod("max").invoke(annotation);
        require(
            min >= 0 && max >= 0,
            format(
                "@%s(min=%d, max=%d): min and max must be greater than or equal to 0.",
                name, min, max));
        require(
            min <= max,
            format("@%s(min=%d, max=%d): min must be less than or equal to max.", name, min, max));
        // It's not very useful to have an always-empty container, however, sometimes when debugging
        // the fuzz target it is!
        if (min == 0 && max == 0) {
          Log.info(
              format(
                  "@%s(min=0, max=0): min and max are both zero. Consider using a"
                      + " constant instead! %n",
                  name));
        }
      } catch (NoSuchMethodException e) {
        throw new RuntimeException("Failed to access min/max fields of annotation", e);
      } catch (InvocationTargetException | IllegalAccessException e) {
        throw new RuntimeException(e);
      }
    }
  }
}
