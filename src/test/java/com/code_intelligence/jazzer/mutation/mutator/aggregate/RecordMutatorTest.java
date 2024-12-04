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

package com.code_intelligence.jazzer.mutation.mutator.aggregate;

import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.mutator.Mutators;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.code_intelligence.jazzer.mutation.utils.PropertyConstraint;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

@SuppressWarnings("unchecked")
class RecordMutatorTest {

  record EmptyRecord() {}

  @Test
  void testEmptyRecord() {
    SerializingMutator<EmptyRecord> mutator =
        (SerializingMutator<EmptyRecord>)
            Mutators.newFactory()
                .createOrThrow(new TypeHolder<@NotNull EmptyRecord>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("[] -> EmptyRecord");
    assertThat(mutator.hasFixedSize()).isTrue();

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      EmptyRecord expected = new EmptyRecord();

      EmptyRecord inited = mutator.init(prng);
      assertThat(inited).isEqualTo(expected);

      EmptyRecord mutated = mutator.mutate(inited, prng);
      assertThat(mutated).isEqualTo(expected);
      assertThat(mutator.detach(mutated)).isSameInstanceAs(mutated);
    }
  }

  record SimpleTypesRecord(boolean bar, int baz) {}

  @Test
  void testSimpleTypesRecord() {
    SerializingMutator<SimpleTypesRecord> mutator =
        (SerializingMutator<SimpleTypesRecord>)
            Mutators.newFactory()
                .createOrThrow(new TypeHolder<@NotNull SimpleTypesRecord>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("[Boolean, Integer] -> SimpleTypesRecord");
    assertThat(mutator.hasFixedSize()).isTrue();
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // Init components, bar = true, no special value for baz, baz = 42
            true,
            4,
            42L,
            // Mutate second component, in range operation, return 23
            1,
            2,
            23L)) {
      SimpleTypesRecord inited = mutator.init(prng);
      assertThat(inited).isNotNull();

      SimpleTypesRecord mutated = mutator.mutate(inited, prng);
      assertThat(mutated.baz()).isEqualTo(23);
      assertThat(mutator.detach(mutated)).isSameInstanceAs(mutated);
    }
  }

  record ContainerTypesRecord(@NotNull List<Integer> list, @NotNull Map<String, Boolean> map) {}

  @Test
  void testContainerTypesRecord() {
    SerializingMutator<ContainerTypesRecord> mutator =
        (SerializingMutator<ContainerTypesRecord>)
            Mutators.newFactory()
                .createOrThrow(new TypeHolder<@NotNull ContainerTypesRecord>() {}.annotatedType());
    assertThat(mutator.toString())
        .isEqualTo(
            "[List<Nullable<Integer>>, Map<Nullable<String>, Nullable<Boolean>>] ->"
                + " ContainerTypesRecord");
    assertThat(mutator.hasFixedSize()).isFalse();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // Init components, 0 list elements, 0 map elements
            0,
            0,
            // Mutate first component, insert, 1 element, 0 offset, not null, first special value
            // "0"
            0,
            0,
            1,
            0,
            false,
            1)) {
      ContainerTypesRecord inited = mutator.init(prng);
      assertThat(inited).isNotNull();

      ContainerTypesRecord mutated = mutator.mutate(inited, prng);
      assertThat(mutated.map).isEqualTo(inited.map);
      assertThat(mutated.list).containsExactly(0);
      assertThat(mutator.detach(mutated)).isSameInstanceAs(mutated);
    }
  }

  record RecursiveTypesRecord(int value, RecursiveTypesRecord next) {}

  @Test
  void testRecursiveTypesRecord() {
    SerializingMutator<RecursiveTypesRecord> mutator =
        (SerializingMutator<RecursiveTypesRecord>)
            Mutators.newFactory()
                .createOrThrow(new TypeHolder<@NotNull RecursiveTypesRecord>() {}.annotatedType());
    assertThat(mutator.toString())
        .isEqualTo(
            "[Integer, Nullable<RecursionBreaking((cycle) -> RecursiveTypesRecord)>] ->"
                + " RecursiveTypesRecord");
    assertThat(mutator.hasFixedSize()).isFalse();

    RecursiveTypesRecord record;
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // --> special value 1
            2
            // record field is null due to recursion
            )) {
      record = mutator.init(prng);
      assertThat(record).isEqualTo(new RecursiveTypesRecord(1, null));
    }

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            1,
            // --> special value 0 for int field in nested record
            1
            // nested record field is null due to recursion
            )) {
      record = mutator.mutate(record, prng);
      assertThat(record).isEqualTo(new RecursiveTypesRecord(1, new RecursiveTypesRecord(0, null)));
      assertThat(mutator.detach(record)).isSameInstanceAs(record);
    }
  }

  record PropagateInnerTypeRecord(List<Integer> list) {}

  record PropagateTypeRecord(PropagateInnerTypeRecord inner) {}

  @Test
  void propagateConstraint() {
    SerializingMutator<@NotNull PropagateTypeRecord> mutator =
        (SerializingMutator<@NotNull PropagateTypeRecord>)
            Mutators.newFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull(constraint = PropertyConstraint.RECURSIVE)
                        PropagateTypeRecord>() {}.annotatedType());
    assertThat(mutator.toString())
        .isEqualTo("[[List<Integer>] -> PropagateInnerTypeRecord] -> PropagateTypeRecord");
  }
}
