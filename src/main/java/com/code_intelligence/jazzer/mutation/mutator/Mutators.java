/*
 * Copyright 2023 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.mutation.mutator;

import static com.code_intelligence.jazzer.mutation.support.TypeSupport.visitAnnotatedType;
import static java.lang.String.format;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.joining;

import com.code_intelligence.jazzer.mutation.annotation.AppliesTo;
import com.code_intelligence.jazzer.mutation.api.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.mutator.collection.CollectionMutators;
import com.code_intelligence.jazzer.mutation.mutator.lang.LangMutators;
import com.code_intelligence.jazzer.mutation.mutator.proto.ProtoMutators;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedType;

public final class Mutators {
  private Mutators() {}

  public static MutatorFactory newFactory() {
    return new ChainedMutatorFactory(
        LangMutators.newFactory(), CollectionMutators.newFactory(), ProtoMutators.newFactory());
  }

  /**
   * Throws an exception if any annotation on {@code type} violates the restrictions of its
   * {@link AppliesTo} meta-annotation.
   */
  public static void validateAnnotationUsage(AnnotatedType type) {
    visitAnnotatedType(type, (clazz, annotations) -> {
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
            helpText += stream(appliesTo.subClassesOf()).map(Class::getName).collect(joining(", "));
          }
          // Use the simple name as our annotations live in a single package.
          throw new IllegalArgumentException(format("%s does not apply to %s, only applies to %s",
              annotation.annotationType().getSimpleName(), clazz.getName(), helpText));
        }
    });
  }
}
