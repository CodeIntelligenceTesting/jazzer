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

import static com.code_intelligence.jazzer.mutation.support.TestSupport.anyPseudoRandom;
import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.engine.ChainedMutatorFactory;
import com.code_intelligence.jazzer.mutation.mutator.Mutators;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.code_intelligence.jazzer.mutation.utils.PropertyConstraint;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

@SuppressWarnings({"unchecked", "unused", "FieldCanBeLocal"})
class CachedConstructorMutatorTest {

  static class EmptyBean {}

  @Test
  void testEmptyBean() {
    assertThat(
            ChainedMutatorFactory.of(Stream.of(new CachedConstructorMutatorFactory()))
                .tryCreate(new TypeHolder<@NotNull EmptyBean>() {}.annotatedType()))
        .isPresent();
  }

  static class SimpleClass {
    private final String foo;
    private final List<Integer> bar;
    private final boolean baz;

    SimpleClass(String foo, List<Integer> bar, boolean baz) {
      this.foo = foo;
      this.bar = bar;
      this.baz = baz;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      SimpleClass that = (SimpleClass) o;
      return baz == that.baz && Objects.equals(foo, that.foo) && Objects.equals(bar, that.bar);
    }

    @Override
    public int hashCode() {
      return Objects.hash(foo, bar, baz);
    }

    @Override
    public String toString() {
      return "SimpleClass{" + "foo='" + foo + '\'' + ", bar=" + bar + ", baz=" + baz + '}';
    }
  }

  @Test
  void mutateSimpleClassWithoutGetter() {
    SerializingMutator<SimpleClass> mutator =
        (SerializingMutator<SimpleClass>)
            Mutators.newFactory()
                .createOrThrow(new TypeHolder<@NotNull SimpleClass>() {}.annotatedType());
    assertThat(mutator.toString())
        .isEqualTo("[Nullable<String>, Nullable<List<Nullable<Integer>>>, Boolean] -> SimpleClass");

    PseudoRandom prng = anyPseudoRandom();
    SimpleClass inited = mutator.init(prng);
    assertThat(inited).isNotNull();

    SimpleClass mutated = mutator.mutate(inited, prng);
    assertThat(mutated).isNotEqualTo(inited);
    assertThat(mutator.detach(mutated)).isNotSameInstanceAs(mutated);
  }

  @Test
  void testMultipleMutations() {
    SerializingMutator<SimpleClass> mutator =
        (SerializingMutator<SimpleClass>)
            Mutators.newFactory()
                .createOrThrow(new TypeHolder<@NotNull SimpleClass>() {}.annotatedType());
    PseudoRandom prng = anyPseudoRandom();
    SimpleClass inited = mutator.init(prng);
    SimpleClass detached = mutator.detach(inited);
    assertThat(inited).isEqualTo(detached);
    SimpleClass value = inited;

    for (int i = 0; i < 3; i++) {
      SimpleClass oldValue = value;
      value = mutator.mutate(oldValue, prng);
      assertThat(value).isNotEqualTo(oldValue);
      assertThat(value).isNotEqualTo(detached);
      assertThat(detached).isEqualTo(inited);
    }
  }

  static class Parent {
    private final Integer foo;

    protected Parent(Integer foo) {
      this.foo = foo;
    }
  }

  static class BeanWithParent extends Parent {
    private final List<Integer> bar;

    protected BeanWithParent(Integer foo, List<Integer> bar) {
      super(foo);
      this.bar = bar;
    }
  }

  @Test
  void testBeanWithParent() {
    SerializingMutator<BeanWithParent> mutator =
        (SerializingMutator<BeanWithParent>)
            Mutators.newFactory()
                .createOrThrow(new TypeHolder<@NotNull BeanWithParent>() {}.annotatedType());
    assertThat(mutator.toString())
        .startsWith("[Nullable<Integer>, Nullable<List<Nullable<Integer>>>] -> BeanWithParent");
    assertThat(mutator.hasFixedSize()).isFalse();

    PseudoRandom prng = anyPseudoRandom();
    BeanWithParent inited = mutator.init(prng);

    BeanWithParent mutated = mutator.mutate(inited, prng);
    assertThat(mutated).isNotEqualTo(inited);
  }

  @Test
  void testCascadePropertyConstraints() {
    SerializingMutator<BeanWithParent> mutator =
        (SerializingMutator<BeanWithParent>)
            Mutators.newFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull(constraint = PropertyConstraint.RECURSIVE)
                        BeanWithParent>() {}.annotatedType());
    assertThat(mutator.toString()).startsWith("[Integer, List<Integer>] -> BeanWithParent");
    assertThat(mutator.hasFixedSize()).isFalse();

    PseudoRandom prng = anyPseudoRandom();
    BeanWithParent inited = mutator.init(prng);

    BeanWithParent mutated = mutator.mutate(inited, prng);
    assertThat(mutated).isNotEqualTo(inited);
  }

  static void emptyInputMethod(SimpleClass simpleClass) {
    // Nothing to do here, only needed for the method reference.
  }
}
