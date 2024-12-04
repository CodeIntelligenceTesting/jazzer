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

import static com.code_intelligence.jazzer.mutation.mutator.proto.BuilderAdapters.makeMutableRepeatedFieldView;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.code_intelligence.jazzer.protobuf.Proto3.RepeatedIntegralField3;
import com.google.protobuf.Descriptors.FieldDescriptor;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

class BuilderAdaptersTest {
  @Test
  void testMakeMutableRepeatedFieldView() {
    RepeatedIntegralField3.Builder builder = RepeatedIntegralField3.newBuilder();
    FieldDescriptor someField = builder.getDescriptorForType().findFieldByNumber(1);
    assertThat(someField).isNotNull();

    List<Integer> view = makeMutableRepeatedFieldView(builder, someField);
    assertThat(builder.build().getSomeFieldList()).isEmpty();

    assertThat(view.add(1)).isTrue();
    assertThat(view.get(0)).isEqualTo(1);
    assertThat(view).hasSize(1);
    assertThat(builder.build().getSomeFieldList()).containsExactly(1).inOrder();
    assertThrows(IndexOutOfBoundsException.class, () -> view.get(1));

    assertThat(view.add(2)).isTrue();
    assertThat(view.add(3)).isTrue();
    assertThat(view).hasSize(3);
    assertThat(builder.build().getSomeFieldList()).containsExactly(1, 2, 3).inOrder();
    assertThrows(IndexOutOfBoundsException.class, () -> view.get(3));

    assertThat(view.set(1, 4)).isEqualTo(2);
    assertThat(view).hasSize(3);
    assertThat(builder.build().getSomeFieldList()).containsExactly(1, 4, 3).inOrder();

    assertThat(view.set(1, 5)).isEqualTo(4);
    assertThat(view).hasSize(3);
    assertThat(builder.build().getSomeFieldList()).containsExactly(1, 5, 3).inOrder();

    assertThat(view.remove(1)).isEqualTo(5);
    assertThat(view).hasSize(2);
    assertThat(builder.build().getSomeFieldList()).containsExactly(1, 3).inOrder();

    assertThrows(IndexOutOfBoundsException.class, () -> view.remove(-1));
    assertThrows(IndexOutOfBoundsException.class, () -> view.remove(2));

    assertThat(view.addAll(1, Collections.emptyList())).isFalse();
    assertThat(view).hasSize(2);
    assertThat(builder.build().getSomeFieldList()).containsExactly(1, 3).inOrder();

    assertThat(view.addAll(1, Arrays.asList(6, 7, 8))).isTrue();
    assertThat(view).hasSize(5);
    assertThat(builder.build().getSomeFieldList()).containsExactly(1, 6, 7, 8, 3).inOrder();

    view.subList(2, 4).clear();
    assertThat(view).hasSize(3);
    assertThat(builder.build().getSomeFieldList()).containsExactly(1, 6, 3).inOrder();

    assertThat(view.addAll(3, Arrays.asList(9, 10))).isTrue();
    assertThat(view).hasSize(5);
    assertThat(builder.build().getSomeFieldList()).containsExactly(1, 6, 3, 9, 10).inOrder();

    view.clear();
    assertThat(view).hasSize(0);
    assertThat(builder.build().getSomeFieldList()).isEmpty();
  }
}
