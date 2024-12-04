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

package com.code_intelligence.jazzer.mutation.combinator;

import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.assemble;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.combine;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateProductInPlace;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateProperty;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateSumInPlace;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateThenMapToImmutable;
import static com.code_intelligence.jazzer.mutation.combinator.MutatorCombinators.mutateViaView;
import static com.code_intelligence.jazzer.mutation.support.InputStreamSupport.infiniteZeros;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockCrossOver;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockCrossOverInPlace;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockInitInPlace;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockMutator;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.nullDataOutputStream;
import static com.google.common.truth.Truth.assertThat;
import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.InPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.Serializer;
import com.code_intelligence.jazzer.mutation.api.SerializingInPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.function.ToIntFunction;
import org.junit.jupiter.api.Test;

class MutatorCombinatorsTest {
  @Test
  void testMutateProperty() {
    InPlaceMutator<Foo> mutator =
        mutateProperty(Foo::getValue, mockMutator(21, value -> 2 * value), Foo::setValue);

    assertThat(mutator.toString()).isEqualTo("Foo.Integer");

    Foo foo = new Foo(0, singletonList(13));

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
  void testCrossOverProperty() {
    InPlaceMutator<Foo> mutator =
        mutateProperty(Foo::getValue, mockCrossOver((a, b) -> 42), Foo::setValue);
    Foo foo = new Foo(0);
    Foo otherFoo = new Foo(1);
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // use foo value
            0)) {
      mutator.crossOverInPlace(foo, otherFoo, prng);
      assertThat(foo.getValue()).isEqualTo(0);
    }
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // use otherFoo value
            1)) {
      mutator.crossOverInPlace(foo, otherFoo, prng);
      assertThat(foo.getValue()).isEqualTo(1);
    }
    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // use property type cross over
            2)) {
      mutator.crossOverInPlace(foo, otherFoo, prng);
      assertThat(foo.getValue()).isEqualTo(42);
    }
  }

  @Test
  void testMutateViaView() {
    InPlaceMutator<Foo> mutator =
        mutateViaView(
            Foo::getList,
            new InPlaceMutator<List<Integer>>() {
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
              public boolean hasFixedSize() {
                return false;
              }

              @Override
              public String toDebugString(Predicate<Debuggable> isInCycle) {
                return "List<Integer>";
              }
            });

    assertThat(mutator.toString()).isEqualTo("Foo via List<Integer>");

    Foo foo = new Foo(13, singletonList(13));

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
  void testCrossOverViaView() {
    InPlaceMutator<Foo> mutator =
        mutateViaView(
            Foo::getList,
            mockCrossOverInPlace(
                (a, b) -> {
                  a.clear();
                  a.add(42);
                }));

    Foo foo = new Foo(0, singletonList(0));
    Foo otherFoo = new Foo(0, singletonList(1));
    try (MockPseudoRandom prng = mockPseudoRandom()) {
      mutator.crossOverInPlace(foo, otherFoo, prng);
      assertThat(foo.getList()).containsExactly(42);
    }
  }

  @Test
  void testMutateCombine() {
    InPlaceMutator<Foo> valueMutator =
        mutateProperty(Foo::getValue, mockMutator(21, value -> 2 * value), Foo::setValue);

    InPlaceMutator<Foo> listMutator =
        mutateViaView(
            Foo::getList,
            new InPlaceMutator<List<Integer>>() {
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
              public boolean hasFixedSize() {
                return false;
              }

              @Override
              public String toDebugString(Predicate<Debuggable> isInCycle) {
                return "List<Integer>";
              }
            });
    InPlaceMutator<Foo> mutator = combine(valueMutator, listMutator);

    assertThat(mutator.toString()).isEqualTo("{Foo.Integer, Foo via List<Integer>}");

    Foo foo = new Foo(13, singletonList(13));

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
  void testCrossOverCombine() {
    InPlaceMutator<Foo> valueMutator =
        mutateProperty(Foo::getValue, mockCrossOver((a, b) -> 42), Foo::setValue);
    InPlaceMutator<Foo> listMutator =
        mutateViaView(
            Foo::getList,
            mockCrossOverInPlace(
                (a, b) -> {
                  a.clear();
                  a.add(42);
                }));
    InPlaceMutator<Foo> mutator = combine(valueMutator, listMutator);

    Foo foo = new Foo(0, singletonList(0));
    Foo fooOther = new Foo(1, singletonList(1));

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // call cross over in property mutator
            2)) {
      mutator.crossOverInPlace(foo, fooOther, prng);
    }
    assertThat(foo.getValue()).isEqualTo(42);
    assertThat(foo.getList()).containsExactly(42);
  }

  @Test
  void testCrossOverEmptyCombine() {
    Foo foo = new Foo(0, singletonList(0));
    Foo fooOther = new Foo(1, singletonList(1));
    InPlaceMutator<Foo> emptyCombineMutator = combine();
    try (MockPseudoRandom prng = mockPseudoRandom()) {
      emptyCombineMutator.crossOverInPlace(foo, fooOther, prng);
    }
    assertThat(foo.getValue()).isEqualTo(0);
    assertThat(foo.getList()).containsExactly(0);
  }

  @Test
  void testMutateAssemble() {
    InPlaceMutator<Foo> valueMutator =
        mutateProperty(Foo::getValue, mockMutator(21, value -> 2 * value), Foo::setValue);

    InPlaceMutator<Foo> listMutator =
        mutateViaView(
            Foo::getList,
            new InPlaceMutator<List<Integer>>() {
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
              public boolean hasFixedSize() {
                return true;
              }

              @Override
              public String toDebugString(Predicate<Debuggable> isInCycle) {
                return "List<Integer>";
              }
            });

    SerializingInPlaceMutator<Foo> mutator =
        assemble(
            (m) -> {},
            () -> new Foo(0, singletonList(0)),
            new Serializer<Foo>() {
              @Override
              public Foo read(DataInputStream in) {
                return null;
              }

              @Override
              public void write(Foo value, DataOutputStream out) {}

              @Override
              public Foo detach(Foo value) {
                return null;
              }
            },
            () -> combine(valueMutator, listMutator));

    assertThat(mutator.toString()).isEqualTo("{Foo.Integer, Foo via List<Integer>}");

    Foo foo = new Foo(13, singletonList(13));

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
  void testCrossOverAssemble() {
    InPlaceMutator<Foo> valueMutator =
        mutateProperty(Foo::getValue, mockCrossOver((a, b) -> 42), Foo::setValue);

    InPlaceMutator<Foo> listMutator =
        mutateViaView(
            Foo::getList,
            mockCrossOverInPlace(
                (a, b) -> {
                  a.clear();
                  a.add(42);
                }));

    SerializingInPlaceMutator<Foo> mutator =
        assemble(
            (m) -> {},
            () -> new Foo(0, singletonList(0)),
            new Serializer<Foo>() {
              @Override
              public Foo read(DataInputStream in) {
                return null;
              }

              @Override
              public void write(Foo value, DataOutputStream out) {}

              @Override
              public Foo detach(Foo value) {
                return null;
              }
            },
            () -> combine(valueMutator, listMutator));

    Foo foo = new Foo(0, singletonList(0));
    Foo fooOther = new Foo(1, singletonList(1));

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // cross over in property mutator
            2)) {
      mutator.crossOverInPlace(foo, fooOther, prng);
    }
    assertThat(foo.getValue()).isEqualTo(42);
    assertThat(foo.getList()).containsExactly(42);
  }

  @Test
  void testMutateThenMapToImmutable() throws IOException {
    SerializingMutator<char[]> charMutator =
        mockMutator(
            new char[] {'H', 'e', 'l', 'l', 'o'},
            chars -> {
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
    assertThrows(
        UnsupportedOperationException.class,
        () -> mutator.write(capturedValue, nullDataOutputStream()));
  }

  @Test
  void testCrossOverThenMapToImmutable() {
    SerializingMutator<char[]> charMutator =
        mockCrossOver(
            (a, b) -> {
              assertThat(a).isEqualTo(new char[] {'H', 'e', 'l', 'l', 'o'});
              assertThat(b).isEqualTo(new char[] {'W', 'o', 'r', 'l', 'd'});
              return new char[] {'T', 'e', 's', 't', 'e', 'd'};
            });
    SerializingMutator<String> mutator =
        mutateThenMapToImmutable(charMutator, String::new, String::toCharArray);

    String crossedOver;
    try (MockPseudoRandom prng = mockPseudoRandom()) {
      crossedOver = mutator.crossOver("Hello", "World", prng);
    }
    assertThat(crossedOver).isEqualTo("Tested");
  }

  @Test
  void testCrossOverProduct() {
    SerializingMutator<Boolean> mutator1 = mockCrossOver((a, b) -> true);
    SerializingMutator<Integer> mutator2 = mockCrossOver((a, b) -> 42);
    InPlaceProductMutator mutator = mutateProductInPlace(mutator1, mutator2);

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // use first value in mutator1
            0,
            // use second value in mutator2
            0)) {
      Object[] crossedOver =
          mutator.crossOver(new Object[] {false, 0}, new Object[] {true, 1}, prng);
      assertThat(crossedOver).isEqualTo(new Object[] {false, 0});
    }

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // use first value in mutator1
            1,
            // use second value in mutator2
            1)) {
      Object[] crossedOver =
          mutator.crossOver(new Object[] {false, 0}, new Object[] {true, 1}, prng);
      assertThat(crossedOver).isEqualTo(new Object[] {true, 1});
    }

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // use cross over in mutator1
            2,
            // use cross over in mutator2
            2)) {
      Object[] crossedOver =
          mutator.crossOver(new Object[] {false, 0}, new Object[] {true, 2}, prng);
      assertThat(crossedOver).isEqualTo(new Object[] {true, 42});
    }
  }

  @Test
  void testCrossOverSumInPlaceSameType() {
    ToIntFunction<List<Integer>> mutotarIndexFromValue = (r) -> 0;
    InPlaceMutator<List<Integer>> mutator1 =
        mockCrossOverInPlace(
            (a, b) -> {
              a.add(42);
            });
    InPlaceMutator<List<Integer>> mutator2 = mockCrossOverInPlace((a, b) -> {});
    InPlaceMutator<List<Integer>> mutator =
        mutateSumInPlace(mutotarIndexFromValue, mutator1, mutator2);

    List<Integer> a = new ArrayList<>();
    List<Integer> b = new ArrayList<>();

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      mutator.crossOverInPlace(a, b, prng);
    }
    assertThat(a).containsExactly(42);
  }

  @Test
  void testCrossOverSumInPlaceIndeterminate() {
    InPlaceMutator<List<?>> mutator1 = mockCrossOverInPlace((a, b) -> {});
    InPlaceMutator<List<?>> mutator2 = mockCrossOverInPlace((a, b) -> {});
    ToIntFunction<List<?>> bothIndeterminate = (r) -> -1;

    InPlaceMutator<List<?>> mutator = mutateSumInPlace(bothIndeterminate, mutator1, mutator2);

    List<Integer> a = new ArrayList<>();
    a.add(42);
    List<Integer> b = new ArrayList<>();

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      mutator.crossOverInPlace(a, b, prng);
      assertThat(a).containsExactly(42);
    }
  }

  @Test
  void testCrossOverSumInPlaceFirstIndeterminate() {
    List<Integer> reference = new ArrayList<>();
    List<Integer> otherReference = new ArrayList<>();

    InPlaceMutator<List<Integer>> mutator1 = mockCrossOverInPlace((a, b) -> {});
    InPlaceMutator<List<Integer>> mutator2 =
        mockInitInPlace(
            (l) -> {
              l.add(42);
            });
    ToIntFunction<List<Integer>> firstIndeterminate = (r) -> r == reference ? -1 : 1;

    InPlaceMutator<List<Integer>> mutator =
        mutateSumInPlace(firstIndeterminate, mutator1, mutator2);

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      mutator.crossOverInPlace(reference, otherReference, prng);
      assertThat(reference).containsExactly(42);
    }
  }

  static class Foo {
    private int value;
    private final List<Integer> list;

    public Foo(int value) {
      this(value, new ArrayList<>());
    }

    public Foo(int value, List<Integer> list) {
      this.value = value;
      this.list = new ArrayList<>(list);
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
