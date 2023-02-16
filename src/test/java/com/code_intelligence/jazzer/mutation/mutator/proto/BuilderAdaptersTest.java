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

import static com.code_intelligence.jazzer.mutation.mutator.proto.BuilderAdapters.makeMutableRepeatedFieldView;
import static com.code_intelligence.jazzer.mutation.mutator.proto.BuilderAdapters.makeMutableRepeatedMessageFieldView;
import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.code_intelligence.jazzer.protobuf.Proto3.PrimitiveField3;
import com.code_intelligence.jazzer.protobuf.Proto3.RepeatedMessageField3;
import com.code_intelligence.jazzer.protobuf.Proto3.RepeatedPrimitiveField3;
import com.google.common.truth.Correspondence;
import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Message;
import com.google.protobuf.Message.Builder;
import java.util.List;
import org.junit.jupiter.api.Test;

class BuilderAdaptersTest {
  private static final Correspondence<Builder, Message> AS_MESSAGE =
      Correspondence.transforming(Builder::build, "as Message");

  @Test
  void testMakeMutableRepeatedFieldView() {
    RepeatedPrimitiveField3.Builder builder = RepeatedPrimitiveField3.newBuilder();
    FieldDescriptor someField = builder.getDescriptorForType().findFieldByNumber(1);
    assertThat(someField).isNotNull();

    List<Boolean> view = makeMutableRepeatedFieldView(builder, someField);
    assertThat(view).isEmpty();

    assertThat(view.add(true)).isTrue();
    assertThat(view.get(0)).isTrue();
    assertThat(view).hasSize(1);
    assertThat(view).containsExactly(true).inOrder();
    assertThrows(IndexOutOfBoundsException.class, () -> view.get(1));

    assertThat(view.add(false)).isTrue();
    assertThat(view.add(true)).isTrue();
    assertThat(view).hasSize(3);
    assertThat(view).containsExactly(true, false, true).inOrder();
    assertThrows(IndexOutOfBoundsException.class, () -> view.get(3));

    assertThat(view.set(1, true)).isFalse();
    assertThat(view).hasSize(3);
    assertThat(view).containsExactly(true, true, true).inOrder();

    assertThat(view.set(1, false)).isTrue();
    assertThat(view).hasSize(3);
    assertThat(view).containsExactly(true, false, true).inOrder();

    assertThat(view.remove(1)).isFalse();
    assertThat(view).hasSize(2);
    assertThat(view).containsExactly(true, true).inOrder();

    assertThrows(IndexOutOfBoundsException.class, () -> view.remove(-1));
    assertThrows(IndexOutOfBoundsException.class, () -> view.remove(2));
  }

  @Test
  void testMakeMutableRepeatedMessageFieldView() {
    RepeatedMessageField3.Builder builder = RepeatedMessageField3.newBuilder();
    FieldDescriptor messageField = builder.getDescriptorForType().findFieldByNumber(1);
    FieldDescriptor someField = PrimitiveField3.getDescriptor().getFields().get(0);
    assertThat(messageField).isNotNull();

    PrimitiveField3 FALSE_MSG = PrimitiveField3.newBuilder().build();
    PrimitiveField3 TRUE_MSG = PrimitiveField3.newBuilder().setSomeField(true).build();

    List<Builder> view = makeMutableRepeatedMessageFieldView(builder, messageField);
    assertThat(view).isEmpty();

    assertThat(view.add(PrimitiveField3.newBuilder().setSomeField(true))).isTrue();
    assertThat(view.get(0).build()).isEqualTo(TRUE_MSG);
    assertThat(view).hasSize(1);
    assertThat(view).comparingElementsUsing(AS_MESSAGE).containsExactly(TRUE_MSG).inOrder();
    assertThrows(IndexOutOfBoundsException.class, () -> view.get(1));

    assertThat(view.add(PrimitiveField3.newBuilder())).isTrue();
    assertThat(view.add(PrimitiveField3.newBuilder().setSomeField(true))).isTrue();
    assertThat(view).hasSize(3);
    assertThat(view)
        .comparingElementsUsing(AS_MESSAGE)
        .containsExactly(TRUE_MSG, FALSE_MSG, TRUE_MSG)
        .inOrder();
    assertThrows(IndexOutOfBoundsException.class, () -> view.get(3));

    assertThat(view.set(1, PrimitiveField3.newBuilder().setSomeField(true)).build())
        .isEqualTo(FALSE_MSG);
    assertThat(view).hasSize(3);
    assertThat(view)
        .comparingElementsUsing(AS_MESSAGE)
        .containsExactly(TRUE_MSG, TRUE_MSG, TRUE_MSG)
        .inOrder();

    assertThat(view.set(1, PrimitiveField3.newBuilder()).build()).isEqualTo(TRUE_MSG);
    assertThat(view).hasSize(3);
    assertThat(view)
        .comparingElementsUsing(AS_MESSAGE)
        .containsExactly(TRUE_MSG, FALSE_MSG, TRUE_MSG)
        .inOrder();

    assertThat(view.remove(1).build()).isEqualTo(FALSE_MSG);
    assertThat(view).hasSize(2);
    assertThat(view)
        .comparingElementsUsing(AS_MESSAGE)
        .containsExactly(TRUE_MSG, TRUE_MSG)
        .inOrder();

    assertThrows(IndexOutOfBoundsException.class, () -> view.remove(-1));
    assertThrows(IndexOutOfBoundsException.class, () -> view.remove(2));
  }
}
