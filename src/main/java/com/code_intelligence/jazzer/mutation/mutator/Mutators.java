/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator;

import static com.code_intelligence.jazzer.mutation.support.TypeSupport.visitAnnotatedType;
import static java.lang.String.format;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.joining;

import com.code_intelligence.jazzer.mutation.annotation.AppliesTo;
import com.code_intelligence.jazzer.mutation.api.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.mutator.aggregate.AggregateMutators;
import com.code_intelligence.jazzer.mutation.mutator.collection.CollectionMutators;
import com.code_intelligence.jazzer.mutation.mutator.lang.LangMutators;
import com.code_intelligence.jazzer.mutation.mutator.libfuzzer.LibFuzzerMutators;
import com.code_intelligence.jazzer.mutation.mutator.proto.ProtoMutators;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedType;

public final class Mutators {
  private Mutators() {}

  public static MutatorFactory newFactory() {
    return new ChainedMutatorFactory(
        LangMutators.newFactory(),
        CollectionMutators.newFactory(),
        ProtoMutators.newFactory(),
        LibFuzzerMutators.newFactory(),
        AggregateMutators.newFactory());
  }

  /**
   * Throws an exception if any annotation on {@code type} violates the restrictions of its {@link
   * AppliesTo} meta-annotation.
   */
  public static void validateAnnotationUsage(AnnotatedType type) {
    visitAnnotatedType(
        type,
        (clazz, annotations) -> {
          outer:
          for (Annotation annotation : annotations) {
            AppliesTo appliesTo = annotation.annotationType().getAnnotation(AppliesTo.class);
            if (appliesTo == null) {
              continue;
            }
            for (Class<?> allowedClass : appliesTo.value()) {
              if (allowedClass == clazz) {
                continue outer;
              }
            }
            for (Class<?> allowedSuperClass : appliesTo.subClassesOf()) {
              if (allowedSuperClass.isAssignableFrom(clazz)) {
                continue outer;
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
              helpText +=
                  stream(appliesTo.subClassesOf()).map(Class::getName).collect(joining(", "));
            }
            // Use the simple name as our annotations live in a single package.
            throw new IllegalArgumentException(
                format(
                    "%s does not apply to %s, only applies to %s",
                    annotation.annotationType().getSimpleName(), clazz.getName(), helpText));
          }
        });
  }
}
