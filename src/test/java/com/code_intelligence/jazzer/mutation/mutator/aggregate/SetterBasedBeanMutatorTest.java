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
import java.util.Objects;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

@SuppressWarnings("unchecked")
class SetterBasedBeanMutatorTest {

  static class EmptyBean {}

  @Test
  void testEmptyBean() {
    assertThat(
            ChainedMutatorFactory.of(Stream.of(new SetterBasedBeanMutatorFactory()))
                .tryCreate(new TypeHolder<@NotNull EmptyBean>() {}.annotatedType()))
        .isEmpty();
  }

  public static class SimpleTypeBean {
    private boolean foo;
    private String bar;
    private int baz;

    boolean isFoo() {
      return foo;
    }

    void setFoo(boolean foo) {
      this.foo = foo;
    }

    public String getBar() {
      return bar;
    }

    public int getBaz() {
      return baz;
    }

    // Out-of-order setters are supported.
    public void setBaz(int baz) {
      this.baz = baz;
    }

    // Chainable setters are supported.
    public SimpleTypeBean setBar(String bar) {
      this.bar = bar;
      return this;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      SimpleTypeBean that = (SimpleTypeBean) o;
      return foo == that.foo && baz == that.baz && Objects.equals(bar, that.bar);
    }

    @Override
    public int hashCode() {
      return Objects.hash(foo, bar, baz);
    }

    @Override
    public String toString() {
      return "SimpleTypeBean{" + "foo=" + foo + ", bar='" + bar + '\'' + ", baz=" + baz + '}';
    }
  }

  @Test
  void testSimpleTypeBean() {
    SerializingMutator<SimpleTypeBean> mutator =
        (SerializingMutator<SimpleTypeBean>)
            Mutators.newFactory()
                .createOrThrow(new TypeHolder<@NotNull SimpleTypeBean>() {}.annotatedType());
    assertThat(mutator.toString())
        .startsWith("[Nullable<String>, Integer, Boolean] -> SimpleTypeBean");
    assertThat(mutator.hasFixedSize()).isFalse();

    PseudoRandom prng = anyPseudoRandom();
    SimpleTypeBean inited = mutator.init(prng);
    SimpleTypeBean mutated = mutator.mutate(inited, prng);
    assertThat(mutated).isNotEqualTo(inited);

    SimpleTypeBean detached = mutator.detach(mutated);
    assertThat(detached).isEqualTo(mutated);
    assertThat(detached).isNotSameInstanceAs(mutated);
  }

  static class RecursiveTypeBean {
    private final int foo;
    private final RecursiveTypeBean bar;

    public RecursiveTypeBean() {
      this(0, null);
    }

    private RecursiveTypeBean(int foo, RecursiveTypeBean bar) {
      this.foo = foo;
      this.bar = bar;
    }

    public int getFoo() {
      return foo;
    }

    public RecursiveTypeBean setFoo(int foo) {
      return new RecursiveTypeBean(foo, bar);
    }

    public RecursiveTypeBean withBar(RecursiveTypeBean bar) {
      return new RecursiveTypeBean(foo, bar);
    }

    public RecursiveTypeBean getBar() {
      return bar;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      RecursiveTypeBean that = (RecursiveTypeBean) o;
      return foo == that.foo && Objects.equals(bar, that.bar);
    }

    @Override
    public int hashCode() {
      return Objects.hash(foo, bar);
    }

    @Override
    public String toString() {
      return "RecursiveTypeBean{" + "foo=" + foo + ", bar=" + bar + '}';
    }
  }

  @Test
  void testRecursiveTypeBean() {
    SerializingMutator<RecursiveTypeBean> mutator =
        (SerializingMutator<RecursiveTypeBean>)
            Mutators.newFactory()
                .createOrThrow(new TypeHolder<@NotNull RecursiveTypeBean>() {}.annotatedType());
    assertThat(mutator.toString())
        .startsWith(
            "[Integer, Nullable<RecursionBreaking((cycle) -> RecursiveTypeBean)>] ->"
                + " RecursiveTypeBean");
    assertThat(mutator.hasFixedSize()).isFalse();

    PseudoRandom prng = anyPseudoRandom();
    RecursiveTypeBean inited = mutator.init(prng);

    RecursiveTypeBean mutated = mutator.mutate(inited, prng);
    assertThat(mutated).isNotEqualTo(inited);
  }

  public static class BeanWithParent extends SimpleTypeBean {
    protected long quz;

    public long getQuz() {
      return quz;
    }

    public void setQuz(long quz) {
      this.quz = quz;
    }
  }

  @Test
  void testBeanWithParent() {
    SerializingMutator<BeanWithParent> mutator =
        (SerializingMutator<BeanWithParent>)
            Mutators.newFactory()
                .createOrThrow(new TypeHolder<@NotNull BeanWithParent>() {}.annotatedType());
    assertThat(mutator.toString())
        .startsWith("[Nullable<String>, Integer, Boolean, Long] -> BeanWithParent");
    assertThat(mutator.hasFixedSize()).isFalse();

    PseudoRandom prng = anyPseudoRandom();
    BeanWithParent inited = mutator.init(prng);

    BeanWithParent mutated = mutator.mutate(inited, prng);
    assertThat(mutated).isNotEqualTo(inited);
  }

  @Test
  void propagateConstraint() {
    SerializingMutator<@NotNull RecursiveTypeBean> mutator =
        (SerializingMutator<@NotNull RecursiveTypeBean>)
            Mutators.newFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull(constraint = PropertyConstraint.RECURSIVE)
                        RecursiveTypeBean>() {}.annotatedType());
    assertThat(mutator.toString())
        .isEqualTo(
            "[Integer, RecursionBreaking((cycle) -> RecursiveTypeBean)] -> RecursiveTypeBean");
  }
}
