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

import static com.code_intelligence.jazzer.mutation.support.TypeSupport.asAnnotatedType;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.withTypeArguments;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.code_intelligence.jazzer.mutation.support.TypeSupport;
import com.google.protobuf.ByteString;
import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Message.Builder;
import java.lang.reflect.AnnotatedType;
import java.util.List;
import java.util.Optional;

final class TypeLibrary {
  private static final AnnotatedType RAW_LIST = new TypeHolder<@NotNull List>() {}.annotatedType();

  static <T extends Builder> Optional<AnnotatedType> getTypeToMutate(
      FieldDescriptor field, T builder) {
    if (field.isMapField()) {
      emitUnsupportedFieldWarning(field, "MAP");
      return Optional.empty();
    }
    if (field.isRequired()) {
      return getBaseType(field, builder);
    } else if (field.isRepeated()) {
      return getBaseType(field, builder)
          .map(elementType -> withTypeArguments(RAW_LIST, elementType));
    } else if (field.hasPresence()) {
      return getBaseTypeWithPresence(field, builder);
    } else {
      return getBaseType(field, builder);
    }
  }

  private static <T extends Builder> Optional<AnnotatedType> getBaseType(
      FieldDescriptor field, T builder) {
    return getBaseTypeWithPresence(field, builder).map(TypeSupport::notNull);
  }

  @SuppressWarnings("DuplicateBranchesInSwitch") /* False positives caused by TypeHolder */
  private static <T extends Builder> Optional<AnnotatedType> getBaseTypeWithPresence(
      FieldDescriptor field, T builder) {
    switch (field.getJavaType()) {
      case BOOLEAN:
        return Optional.of(new TypeHolder<Boolean>() {}.annotatedType());
      case MESSAGE:
        return Optional.of(asAnnotatedType(builder.newBuilderForField(field).getClass()));
      case INT:
        return Optional.of(new TypeHolder<Integer>() {}.annotatedType());
      case LONG:
        return Optional.of(new TypeHolder<Long>() {}.annotatedType());
      case BYTE_STRING:
        return Optional.of(new TypeHolder<ByteString>() {}.annotatedType());
      case STRING:
        return Optional.of(new TypeHolder<String>() {}.annotatedType());
      case FLOAT:
      case DOUBLE:
      case ENUM:
        emitUnsupportedFieldWarning(field, field.getJavaType());
        return Optional.empty();
      default:
        throw new IllegalStateException("Unexpected type: " + field.getType());
    }
  }

  private static void emitUnsupportedFieldWarning(FieldDescriptor field, Object type) {
    // Not using Log as we don't the mutation framework to depend on Jazzer internals. This function
    // is only a temporary measure anyway until we support all field types.
    System.err.printf(
        "WARN: Proto field %s of type %s is currently unsupported and will not be mutated%n",
        field.getName(), type);
  }

  private TypeLibrary() {}
}
