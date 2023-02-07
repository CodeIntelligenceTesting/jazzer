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

package com.code_intelligence.jazzer.mutation.mutator.proto;

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.combine;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateProperty;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateViaView;
import static com.code_intelligence.jazzer.mutation.mutator.proto.BuilderAdapters.getMutableRepeatedFieldView;
import static com.code_intelligence.jazzer.mutation.mutator.proto.BuilderAdapters.getPresentFieldOrNull;
import static com.code_intelligence.jazzer.mutation.mutator.proto.BuilderAdapters.setFieldWithPresence;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asAnnotatedType;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.findFirstParentIfClass;
import static java.util.Objects.requireNonNull;

import com.code_intelligence.jazzer.mutation.api.InPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.MutatorFactory;
import com.code_intelligence.jazzer.mutation.api.ValueMutator;
import com.google.protobuf.Descriptors.Descriptor;
import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Message.Builder;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Optional;

public final class BuilderMutatorFactory {
  private static <T extends Builder> Descriptor getDescriptor(Class<T> builderClass) {
    Method getDescriptor;
    try {
      getDescriptor = builderClass.getMethod("getDescriptor");
    } catch (NoSuchMethodException e) {
      throw new IllegalStateException(e);
    }
    Descriptor descriptor;
    try {
      descriptor = (Descriptor) getDescriptor.invoke(null);
    } catch (IllegalAccessException | InvocationTargetException e) {
      throw new IllegalStateException(e);
    }
    return descriptor;
  }

  private static <T extends Builder, U> InPlaceMutator<T> mutatorForField(
      FieldDescriptor field, MutatorFactory factory) {
    AnnotatedType typeToMutate = TypeLibrary.getTypeToMutate(field);
    requireNonNull(typeToMutate, () -> "Java class not specified for " + field);

    if (field.isRepeated()) {
      InPlaceMutator<List<U>> underlyingMutator =
          (InPlaceMutator<List<U>>) factory.createInPlaceOrThrow(typeToMutate);
      return mutateViaView(
          builder -> getMutableRepeatedFieldView(builder, field), underlyingMutator);
    } else if (field.hasPresence()) {
      ValueMutator<U> underlyingMutator = (ValueMutator<U>) factory.createOrThrow(typeToMutate);
      return mutateProperty(builder
          -> getPresentFieldOrNull(builder, field),
          underlyingMutator, (builder, value) -> setFieldWithPresence(builder, field, value));
    } else {
      ValueMutator<U> underlyingMutator = (ValueMutator<U>) factory.createOrThrow(typeToMutate);
      return mutateProperty(builder
          -> (U) builder.getField(field),
          underlyingMutator, (builder, value) -> builder.setField(field, value));
    }
  }

  public <T extends Builder> Optional<InPlaceMutator<T>> tryCreate(
      Class<T> builderClass, MutatorFactory factory) {
    return findFirstParentIfClass(asAnnotatedType(builderClass), Builder.class)
        .map(parent
            -> combine(getDescriptor(builderClass)
                           .getFields()
                           .stream()
                           .map(fieldDescriptor -> mutatorForField(fieldDescriptor, factory))
                           .toArray(InPlaceMutator[] ::new)));
  }
}