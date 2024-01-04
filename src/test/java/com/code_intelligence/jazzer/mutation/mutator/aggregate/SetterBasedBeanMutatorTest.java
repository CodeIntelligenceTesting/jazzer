/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.mutator.aggregate;

import static com.code_intelligence.jazzer.mutation.support.TestSupport.anyPseudoRandom;
import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.mutator.Mutators;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import java.util.Objects;
import org.junit.jupiter.api.Test;

@SuppressWarnings("unchecked")
class SetterBasedBeanMutatorTest {

  static class EmptyBean {
    @Override
    public int hashCode() {
      return super.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
      return obj instanceof EmptyBean;
    }
  }

  @Test
  void testEmptyBean() {
    SerializingMutator<EmptyBean> mutator =
        (SerializingMutator<EmptyBean>)
            Mutators.newFactory()
                .createOrThrow(new TypeHolder<@NotNull EmptyBean>() {}.annotatedType());
    assertThat(mutator.toString()).startsWith("[] -> EmptyBean");
    assertThat(mutator.hasFixedSize()).isTrue();

    try (MockPseudoRandom prng = mockPseudoRandom()) {
      // Mutator creates a new instance on init.
      EmptyBean inited = mutator.init(prng);
      assertThat(inited).isEqualTo(new EmptyBean());
      assertThat(inited).isNotSameInstanceAs(new EmptyBean());

      // Create a new instance on mutate as EmptyBean may have hidden state.
      EmptyBean mutated = mutator.mutate(inited, prng);
      assertThat(mutated).isEqualTo(inited);
      assertThat(mutated).isNotSameInstanceAs(inited);
    }
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
}
