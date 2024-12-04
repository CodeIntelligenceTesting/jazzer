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
import com.code_intelligence.jazzer.mutation.mutator.Mutators;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.code_intelligence.jazzer.mutation.utils.PropertyConstraint;
import org.junit.jupiter.api.Test;

public class SuperBuilderMutatorTest {

  @SuppressWarnings({"FieldCanBeLocal", "unused"})
  static class Parent {
    private String foo;

    protected Parent(ParentBuilder<?, ?> b) {
      this.foo = b.foo;
    }

    public static ParentBuilder<?, ?> builder() {
      return new ParentBuilderImpl();
    }

    public abstract static class ParentBuilder<C extends Parent, B extends ParentBuilder<C, B>> {
      private String foo;

      public ParentBuilder() {}

      public B foo(String foo) {
        this.foo = foo;
        return this.self();
      }

      protected abstract B self();

      public abstract C build();

      public String toString() {
        return "Parent.ParentBuilder(foo=" + this.foo + ")";
      }
    }

    private static final class ParentBuilderImpl extends ParentBuilder<Parent, ParentBuilderImpl> {
      private ParentBuilderImpl() {}

      protected ParentBuilderImpl self() {
        return this;
      }

      public Parent build() {
        return new Parent(this);
      }
    }
  }

  @Test
  void testMutateSuperBuilderClass() {
    SerializingMutator<Parent> mutator =
        (SerializingMutator<Parent>)
            Mutators.newFactory()
                .createOrThrow(new TypeHolder<@NotNull Parent>() {}.annotatedType());
    assertThat(mutator.toString()).startsWith("[[Nullable<String>] -> ParentBuilder] -> Parent");

    assertThat(mutator.hasFixedSize()).isFalse();

    PseudoRandom prng = anyPseudoRandom();
    Parent inited = mutator.init(prng);

    Parent mutated = mutator.mutate(inited, prng);
    assertThat(mutated).isNotEqualTo(inited);
  }

  @Test
  void cascadePropertyConstraints() {
    SerializingMutator<Parent> mutator =
        (SerializingMutator<Parent>)
            Mutators.newFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull(constraint = PropertyConstraint.RECURSIVE)
                        Parent>() {}.annotatedType());
    assertThat(mutator.toString()).startsWith("[[String] -> ParentBuilder] -> Parent");
  }

  static class Child extends Parent {
    private boolean bar;

    protected Child(ChildBuilder<?, ?> b) {
      super(b);
      this.bar = b.bar;
    }

    public static ChildBuilder<?, ?> builder() {
      return new ChildBuilderImpl();
    }

    public abstract static class ChildBuilder<C extends Child, B extends ChildBuilder<C, B>>
        extends Parent.ParentBuilder<C, B> {
      private boolean bar;

      public ChildBuilder() {}

      public B bar(boolean bar) {
        this.bar = bar;
        return this.self();
      }

      protected abstract B self();

      public abstract C build();

      public String toString() {
        String var10000 = super.toString();
        return "Child.ChildBuilder(super=" + var10000 + ", bar=" + this.bar + ")";
      }
    }

    private static final class ChildBuilderImpl extends ChildBuilder<Child, ChildBuilderImpl> {
      private ChildBuilderImpl() {}

      protected ChildBuilderImpl self() {
        return this;
      }

      public Child build() {
        return new Child(this);
      }
    }
  }

  @Test
  void testMutateSuperBuilderClassWithParent() {
    SerializingMutator<Child> mutator =
        (SerializingMutator<Child>)
            Mutators.newFactory()
                .createOrThrow(new TypeHolder<@NotNull Child>() {}.annotatedType());
    assertThat(mutator.toString())
        .startsWith("[[Boolean, Nullable<String>] -> ChildBuilder] -> Child");

    assertThat(mutator.hasFixedSize()).isFalse();

    PseudoRandom prng = anyPseudoRandom();
    Child inited = mutator.init(prng);

    Child mutated = mutator.mutate(inited, prng);
    assertThat(mutated).isNotEqualTo(inited);
  }
}
