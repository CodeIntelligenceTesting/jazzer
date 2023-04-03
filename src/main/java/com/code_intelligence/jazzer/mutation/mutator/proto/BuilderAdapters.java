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

import static java.lang.String.format;

import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.MapEntry;
import com.google.protobuf.Message.Builder;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

final class BuilderAdapters {
  static <T extends Builder, U> List<U> makeMutableRepeatedFieldView(
      T builder, FieldDescriptor field) {
    return new AbstractList<U>() {
      @Override
      public U get(int index) {
        return (U) builder.getRepeatedField(field, index);
      }

      @Override
      public int size() {
        return builder.getRepeatedFieldCount(field);
      }

      @Override
      public boolean add(U element) {
        builder.addRepeatedField(field, element);
        return true;
      }

      @Override
      public void add(int index, U element) {
        // TODO: Simply appending and ignoring the index is not perfect
        // but it works. A future revision should try making this a proper
        // append at the given index.
        builder.addRepeatedField(field, element);
      }

      @Override
      public U set(int index, U element) {
        U previous = get(index);
        builder.setRepeatedField(field, index, element);
        return previous;
      }

      @Override
      public U remove(int index) {
        int size = size();
        if (index < 0 || index >= size) {
          throw new IndexOutOfBoundsException(
              format("index %d out of bounds for size %d", index, size));
        }

        ArrayList<U> temp = new ArrayList<>(this);
        builder.clearField(field);

        U removed = temp.get(index);
        for (int i = 0; i < size; i++) {
          if (i != index) {
            builder.addRepeatedField(field, temp.get(i));
          }
        }

        return removed;
      }
    };
  }

  static <T extends Builder, U> U getPresentFieldOrNull(T builder, FieldDescriptor field) {
    if (builder.hasField(field)) {
      return (U) builder.getField(field);
    } else {
      return null;
    }
  }

  static <T extends Builder, U> void setFieldWithPresence(
      T builder, FieldDescriptor field, U value) {
    if (value == null) {
      builder.clearField(field);
    } else {
      builder.setField(field, value);
    }
  }

  static <T extends Builder, K, V> Map<K, V> getMapField(T builder, FieldDescriptor field) {
    int size = builder.getRepeatedFieldCount(field);
    HashMap<K, V> map = new HashMap<>(size);
    for (int i = 0; i < size; i++) {
      MapEntry<K, V> entry = (MapEntry) builder.getRepeatedField(field, i);
      map.put(entry.getKey(), entry.getValue());
    }
    return map;
  }

  static <T extends Builder, K, V> void setMapField(
      Builder builder, FieldDescriptor field, Map<K, V> map) {
    builder.clearField(field);
    for (Entry<K, V> entry : map.entrySet()) {
      MapEntry.Builder<K, V> entryBuilder = (MapEntry.Builder) builder.newBuilderForField(field);
      entryBuilder.setKey(entry.getKey());
      entryBuilder.setValue(entry.getValue());
      builder.addRepeatedField(field, entryBuilder.build());
    }
  }

  private BuilderAdapters() {}
}
