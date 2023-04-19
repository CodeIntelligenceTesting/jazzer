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

package com.code_intelligence.jazzer.mutation.combinator;

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.combine;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateProperty;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateThenMapToImmutable;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateViaView;
import static com.code_intelligence.jazzer.mutation.support.InputStreamSupport.infiniteZeros;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockMutator;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.nullDataOutputStream;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.InPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import org.junit.jupiter.api.Test;

class MutatorCombinatorsTest {
  @Test
  void testMutateProperty() {
    InPlaceMutator<Foo> mutator =
        mutateProperty(Foo::getValue, mockMutator(21, value -> 2 * value), Foo::setValue);

    assertThat(mutator.toString()).isEqualTo("Foo.Integer");

    Foo foo = new Foo(0);
    foo.getList().add(13);

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      mutator.initInPlace(foo, prng);
    }
    assertThat(foo.getValue()).isEqualTo(21);
    assertThat(foo.getList()).containsExactly(13);

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      mutator.mutateInPlace(foo, prng);
    }

    assertThat(foo.getValue()).isEqualTo(42);
    assertThat(foo.getList()).containsExactly(13);
  }

  @Test
  void testMutateViaView() {
    InPlaceMutator<Foo> mutator = mutateViaView(Foo::getList, new InPlaceMutator<List<Integer>>() {
      @Override
      public void initInPlace(List<Integer> reference, PseudoRandom prng) {
        reference.clear();
        reference.add(21);
      }

      @Override
      public void mutateInPlace(List<Integer> reference, PseudoRandom prng) {
        reference.add(reference.get(reference.size() - 1) + 1);
      }

      @Override
      public void crossOverInPlace(
          List<Integer> reference, List<Integer> otherReference, PseudoRandom prng) {}

      @Override
      public String toDebugString(Predicate<Debuggable> isInCycle) {
        return "List<Integer>";
      }
    });

    assertThat(mutator.toString()).isEqualTo("Foo via List<Integer>");

    Foo foo = new Foo(13);
    foo.getList().add(13);

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      mutator.initInPlace(foo, prng);
    }
    assertThat(foo.getValue()).isEqualTo(13);
    assertThat(foo.getList()).containsExactly(21);

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      mutator.mutateInPlace(foo, prng);
    }

    assertThat(foo.getValue()).isEqualTo(13);
    assertThat(foo.getList()).containsExactly(21, 22);
  }

  @Test
  void testCombine() {
    InPlaceMutator<Foo> valueMutator =
        mutateProperty(Foo::getValue, mockMutator(21, value -> 2 * value), Foo::setValue);

    InPlaceMutator<Foo> listMutator =
        mutateViaView(Foo::getList, new InPlaceMutator<List<Integer>>() {
          @Override
          public void initInPlace(List<Integer> reference, PseudoRandom prng) {
            reference.clear();
            reference.add(21);
          }

          @Override
          public void mutateInPlace(List<Integer> reference, PseudoRandom prng) {
            reference.add(reference.get(reference.size() - 1) + 1);
          }

          @Override
          public void crossOverInPlace(
              List<Integer> reference, List<Integer> otherReference, PseudoRandom prng) {}

          @Override
          public String toDebugString(Predicate<Debuggable> isInCycle) {
            return "List<Integer>";
          }
        });
    InPlaceMutator<Foo> mutator = combine(valueMutator, listMutator);

    assertThat(mutator.toString()).isEqualTo("{Foo.Integer, Foo via List<Integer>}");

    Foo foo = new Foo(13);
    foo.getList().add(13);

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      mutator.initInPlace(foo, prng);
    }
    assertThat(foo.getValue()).isEqualTo(21);
    assertThat(foo.getList()).containsExactly(21);

    try (MockPseudoRandom prng = mockPseudoRandom(/* use valueMutator */ 0)) {
      mutator.mutateInPlace(foo, prng);
    }
    assertThat(foo.getValue()).isEqualTo(42);
    assertThat(foo.getList()).containsExactly(21);

    try (MockPseudoRandom prng = mockPseudoRandom(/* use listMutator */ 1)) {
      mutator.mutateInPlace(foo, prng);
    }
    assertThat(foo.getValue()).isEqualTo(42);
    assertThat(foo.getList()).containsExactly(21, 22);
  }

  @Test
  void testMutateThenMapToImmutable() throws IOException {
    SerializingMutator<char[]> charMutator =
        mockMutator(new char[] {'H', 'e', 'l', 'l', 'o'}, chars -> {
          for (int i = 0; i < chars.length; i++) {
            chars[i] ^= (1 << 5);
          }
          chars[chars.length - 1]++;
          return chars;
        });
    SerializingMutator<String> mutator =
        mutateThenMapToImmutable(charMutator, String::new, String::toCharArray);

    assertThat(mutator.toString()).isEqualTo("char[] -> String");

    String value = mutator.read(new DataInputStream(infiniteZeros()));
    assertThat(value).isEqualTo("Hello");

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      value = mutator.mutate(value, prng);
    }
    assertThat(value).isEqualTo("hELLP");

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      value = mutator.mutate(value, prng);
    }
    assertThat(value).isEqualTo("Hellq");

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      value = mutator.init(prng);
    }
    assertThat(value).isEqualTo("Hello");

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      value = mutator.mutate(value, prng);
    }
    assertThat(value).isEqualTo("hELLP");

    final String capturedValue = value;
    assertThrows(UnsupportedOperationException.class,
        () -> mutator.write(capturedValue, nullDataOutputStream()));
  }

  static class Foo {
    private int value;
    private final List<Integer> list;

    public Foo(int value) {
      this.value = value;
      this.list = new ArrayList<>();
    }

    public List<Integer> getList() {
      return list;
    }

    public int getValue() {
      return value;
    }

    public void setValue(int value) {
      this.value = value;
    }
  }
}
