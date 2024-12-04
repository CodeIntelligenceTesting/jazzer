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

package com.code_intelligence.jazzer.mutation.mutator.proto;

import static java.util.Collections.singletonList;

import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Message;
import com.google.protobuf.Message.Builder;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

final class BuilderAdapters {
  private BuilderAdapters() {}

  static <T extends Builder, U> List<U> makeMutableRepeatedFieldView(
      T builder, FieldDescriptor field) {
    return new AbstractList<U>() {
      // O(1)
      @Override
      public U get(int index) {
        return (U) builder.getRepeatedField(field, index);
      }

      // O(1)
      @Override
      public int size() {
        return builder.getRepeatedFieldCount(field);
      }

      // O(1)
      @Override
      public boolean add(U element) {
        builder.addRepeatedField(field, element);
        return true;
      }

      // O(1)
      @Override
      public void add(int index, U element) {
        addAll(index, singletonList(element));
      }

      // O(size() + other.size())
      public boolean addAll(int index, Collection<? extends U> other) {
        // This was benchmarked against the following implementation and found to be faster in all
        // cases (up to 4x on lists of size 1000):
        //
        // for (U element : other) {
        //   builder.addRepeatedField(field, element);
        // }
        // Collections.rotate(subList(index, size()), other.size());
        int otherSize = other.size();
        if (otherSize == 0) {
          return false;
        }

        int originalSize = size();
        if (index == originalSize) {
          for (U element : other) {
            builder.addRepeatedField(field, element);
          }
          return true;
        }

        int newSize = originalSize + otherSize;
        ArrayList<U> temp = new ArrayList<>(newSize);
        for (int i = 0; i < index; i++) {
          temp.add((U) builder.getRepeatedField(field, i));
        }
        temp.addAll(other);
        for (int i = index; i < originalSize; i++) {
          temp.add((U) builder.getRepeatedField(field, i));
        }

        replaceWith(temp);
        return true;
      }

      // O(1)
      @Override
      public U set(int index, U element) {
        U previous = get(index);
        builder.setRepeatedField(field, index, element);
        return previous;
      }

      // O(size())
      @Override
      public U remove(int index) {
        U removed = get(index);
        removeRange(index, index + 1);
        return removed;
      }

      // O(size() - (toIndex - fromIndex))
      @Override
      protected void removeRange(int fromIndex, int toIndex) {
        int originalSize = size();
        int newSize = originalSize - (toIndex - fromIndex);
        if (newSize == 0) {
          builder.clearField(field);
          return;
        }

        // There is no way to remove individual repeated field entries without clearing the entire
        // field, so we have to iterate over all entries and keep them in a temporary list.
        ArrayList<U> temp = new ArrayList<>(newSize);
        for (int i = 0; i < fromIndex; i++) {
          temp.add((U) builder.getRepeatedField(field, i));
        }
        for (int i = toIndex; i < originalSize; i++) {
          temp.add((U) builder.getRepeatedField(field, i));
        }

        replaceWith(temp);
      }

      private void replaceWith(ArrayList<U> temp) {
        builder.clearField(field);
        for (U element : temp) {
          builder.addRepeatedField(field, element);
        }
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
    FieldDescriptor keyField = field.getMessageType().getFields().get(0);
    FieldDescriptor valueField = field.getMessageType().getFields().get(1);
    HashMap<K, V> map = new HashMap<>(size);
    for (int i = 0; i < size; i++) {
      Message entry = (Message) builder.getRepeatedField(field, i);
      map.put((K) entry.getField(keyField), (V) entry.getField(valueField));
    }
    return map;
  }

  static <T extends Builder, K, V> void setMapField(
      Builder builder, FieldDescriptor field, Map<K, V> map) {
    builder.clearField(field);
    FieldDescriptor keyField = field.getMessageType().getFields().get(0);
    FieldDescriptor valueField = field.getMessageType().getFields().get(1);
    Builder entryBuilder = builder.newBuilderForField(field);
    for (Entry<K, V> entry : map.entrySet()) {
      entryBuilder.setField(keyField, entry.getKey());
      entryBuilder.setField(valueField, entry.getValue());
      builder.addRepeatedField(field, entryBuilder.build());
    }
  }
}
