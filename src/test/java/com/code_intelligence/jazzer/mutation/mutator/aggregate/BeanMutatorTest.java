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

class BeanMutatorTest {

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

    public boolean isFoo() {
      return foo;
    }

    public void setFoo(boolean foo) {
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
}
