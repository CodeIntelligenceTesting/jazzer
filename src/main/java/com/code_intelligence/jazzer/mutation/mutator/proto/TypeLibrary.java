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
import java.util.Map;

final class TypeLibrary {
  private static final AnnotatedType RAW_LIST = new TypeHolder<@NotNull List>() {}.annotatedType();
  private static final AnnotatedType RAW_MAP = new TypeHolder<@NotNull Map>() {}.annotatedType();

  static <T extends Builder> AnnotatedType getTypeToMutate(FieldDescriptor field, T builder) {
    if (field.isRequired()) {
      return getBaseType(field, builder);
    } else if (field.isMapField()) {
      // Map fields are represented as repeated message fields, so this check has to come before the
      // one for regular repeated fields.
      //
      // Get a builder for the synthetic MapEntry message used to represent a single entry in the
      // repeated message field representation of a map field.
      Builder entryBuilder = builder.newBuilderForField(field);
      FieldDescriptor keyField = field.getMessageType().getFields().get(0);
      AnnotatedType keyType = getBaseType(keyField, entryBuilder);
      FieldDescriptor valueField = field.getMessageType().getFields().get(1);
      AnnotatedType valueType = getBaseType(valueField, entryBuilder);
      return withTypeArguments(RAW_MAP, keyType, valueType);
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
        return asAnnotatedType(
            builder.newBuilderForField(field).getDefaultInstanceForType().getClass());
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
        return new TypeHolder<Float>() {}.annotatedType();
      case DOUBLE:
        return new TypeHolder<Double>() {}.annotatedType();
      default:
        throw new IllegalStateException("Unexpected type: " + field.getType());
    }
  }

  private TypeLibrary() {}
}
