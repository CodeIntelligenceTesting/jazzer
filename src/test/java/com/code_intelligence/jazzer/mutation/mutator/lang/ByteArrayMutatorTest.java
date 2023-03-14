package com.code_intelligence.jazzer.mutation.mutator.lang;

import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.annotation.WithLength;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import org.junit.jupiter.api.Test;

public class ByteArrayMutatorTest {
  @Test
  void testBasicFunction() {
    SerializingMutator<byte @NotNull[]> mutator =
        (SerializingMutator<byte[]>) LangMutators.newFactory().createOrThrow(
            new TypeHolder<byte @NotNull[]>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("byte[]");

    byte[] arr;
    try (MockPseudoRandom prng = mockPseudoRandom(5, new byte[] {1, 2, 3, 4, 5})) {
      arr = mutator.init(prng);
    }
    assertThat(arr).isEqualTo(new byte[] {1, 2, 3, 4, 5});

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      arr = mutator.mutate(arr, prng);
    }
    assertThat(arr).isEqualTo(new byte[] {2, 4, 6, 8, 10, 6, 7, 8, 9});
  }

  @Test
  void testMaxLength() {
    SerializingMutator<byte[]> mutator =
        (SerializingMutator<byte[]>) LangMutators.newFactory().createOrThrow(
            new TypeHolder<byte @NotNull @WithLength(max = 10)[]>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("byte[]");

    byte[] arr;
    try (MockPseudoRandom prng = mockPseudoRandom(5, new byte[] {1, 2, 3, 4, 5})) {
      arr = mutator.init(prng);
    }
    assertThat(arr).isEqualTo(new byte[] {1, 2, 3, 4, 5});

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      arr = mutator.mutate(arr, prng);
    }
    assertThat(arr).isEqualTo(new byte[] {2, 4, 6, 8, 10, 6, 7, 8, 9});

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      arr = mutator.mutate(arr, prng);
    }
    assertThat(arr).hasLength(10);
    assertThat(arr).isEqualTo(new byte[] {3, 6, 9, 12, 15, 12, 14, 16, 18, 10});

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      arr = mutator.mutate(arr, prng);
    }
    assertThat(arr).hasLength(10);
    assertThat(arr).isEqualTo(new byte[] {4, 8, 12, 16, 20, 18, 21, 24, 27, 20});
  }
}
