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
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.notNull;
import static com.code_intelligence.jazzer.mutation.support.TypeSupport.withTypeArguments;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.google.protobuf.ByteString;
import com.google.protobuf.Descriptors.EnumValueDescriptor;
import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Message.Builder;
import java.lang.reflect.AnnotatedType;
import java.util.List;

final class TypeLibrary {
  private static final AnnotatedType RAW_LIST = new TypeHolder<@NotNull List>() {}.annotatedType();

  static <T extends Builder> AnnotatedType getTypeToMutate(FieldDescriptor field, T builder) {
    if (field.isMapField()) {
      throw new UnsupportedOperationException("Map fields haven't been implemented yet");
    }
    if (field.isRequired()) {
      return getBaseType(field, builder);
    } else if (field.isRepeated()) {
      return withTypeArguments(RAW_LIST, getBaseType(field, builder));
    } else if (field.hasPresence()) {
      return getBaseTypeWithPresence(field, builder);
    } else {
      return getBaseType(field, builder);
    }
  }

  private static <T extends Builder> AnnotatedType getBaseType(FieldDescriptor field, T builder) {
    return notNull(getBaseTypeWithPresence(field, builder));
  }

  @SuppressWarnings("DuplicateBranchesInSwitch") /* False positives caused by TypeHolder */
  private static <T extends Builder> AnnotatedType getBaseTypeWithPresence(
      FieldDescriptor field, T builder) {
    switch (field.getJavaType()) {
      case BOOLEAN:
        return new TypeHolder<Boolean>() {}.annotatedType();
      case MESSAGE:
        return asAnnotatedType(builder.newBuilderForField(field).getClass());
      case INT:
        return new TypeHolder<Integer>() {}.annotatedType();
      case LONG:
        return new TypeHolder<Long>() {}.annotatedType();
      case BYTE_STRING:
        return new TypeHolder<ByteString>() {}.annotatedType();
      case STRING:
        return new TypeHolder<String>() {}.annotatedType();
      case ENUM:
        return new TypeHolder<EnumValueDescriptor>() {}.annotatedType();
      case FLOAT:
      case DOUBLE:
        throw new UnsupportedOperationException(field.getType() + " has not been implemented");
      default:
        throw new IllegalStateException("Unexpected type: " + field.getType());
    }
  }

  private TypeLibrary() {}
}
