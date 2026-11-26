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

import com.code_intelligence.jazzer.mutation.annotation.JazzerIgnore;
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

  public static class Generic<T> {
    T[] t;

    public Generic() {}

    public void setT(T[] t) {
      this.t = t;
    }

    public T[] getT() {
      return t;
    }
  }

  @Test
  void genericClass() {
    SerializingMutator<Generic<String>> mutator =
        (SerializingMutator<Generic<String>>)
            Mutators.newFactory()
                .createOrThrow(new TypeHolder<Generic<String>>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("Nullable<[Nullable<Nullable<String>[]>] -> Generic>");
  }

  public static class Child extends Generic<String> {}

  @Test
  void genericClassChild() {
    SerializingMutator<Child> mutator =
        (SerializingMutator<Child>)
            Mutators.newFactory().createOrThrow(new TypeHolder<Child>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("Nullable<[Nullable<Nullable<String>[]>] -> Child>");
  }

  static class IgnoreOnSetterBean {
    private int kept;
    private String ignored;
    private Object unsupportedWriteOnly;

    public int getKept() {
      return kept;
    }

    public void setKept(int kept) {
      this.kept = kept;
    }

    public String getIgnored() {
      return ignored;
    }

    @JazzerIgnore
    public void setIgnored(String ignored) {
      this.ignored = ignored;
    }

    @JazzerIgnore
    public void setUnsupportedWriteOnly(Object unsupportedWriteOnly) {
      this.unsupportedWriteOnly = unsupportedWriteOnly;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      IgnoreOnSetterBean that = (IgnoreOnSetterBean) o;
      return kept == that.kept
          && Objects.equals(ignored, that.ignored)
          && Objects.equals(unsupportedWriteOnly, that.unsupportedWriteOnly);
    }

    @Override
    public int hashCode() {
      return Objects.hash(kept, ignored, unsupportedWriteOnly);
    }
  }

  @Test
  void testIgnoreOnSetter() {
    SerializingMutator<IgnoreOnSetterBean> mutator =
        (SerializingMutator<IgnoreOnSetterBean>)
            Mutators.newFactory()
                .createOrThrow(new TypeHolder<@NotNull IgnoreOnSetterBean>() {}.annotatedType());
    assertThat(mutator.toString()).startsWith("[Integer] -> IgnoreOnSetterBean");

    PseudoRandom prng = anyPseudoRandom();
    IgnoreOnSetterBean inited = mutator.init(prng);
    IgnoreOnSetterBean mutated = mutator.mutate(inited, prng);
    assertThat(mutated).isNotEqualTo(inited);
    assertThat(inited.ignored).isNull();
    assertThat(mutated.ignored).isNull();
    assertThat(inited.unsupportedWriteOnly).isNull();
    assertThat(mutated.unsupportedWriteOnly).isNull();
  }

  static class IgnoreOnGetterBean {
    private int kept;
    private String ignoredByGetter;
    private boolean ignoredBoolean;
    private Object unsupportedWithIgnoredGetter;

    public int getKept() {
      return kept;
    }

    public void setKept(int kept) {
      this.kept = kept;
    }

    @JazzerIgnore
    public String getIgnoredByGetter() {
      return ignoredByGetter;
    }

    public void setIgnoredByGetter(String ignoredByGetter) {
      this.ignoredByGetter = ignoredByGetter;
    }

    @JazzerIgnore
    public boolean isIgnoredBoolean() {
      return ignoredBoolean;
    }

    public void setIgnoredBoolean(boolean ignoredBoolean) {
      this.ignoredBoolean = ignoredBoolean;
    }

    @JazzerIgnore
    public Object getUnsupportedWithIgnoredGetter() {
      return unsupportedWithIgnoredGetter;
    }

    public void setUnsupportedWithIgnoredGetter(Object unsupportedWithIgnoredGetter) {
      this.unsupportedWithIgnoredGetter = unsupportedWithIgnoredGetter;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      IgnoreOnGetterBean that = (IgnoreOnGetterBean) o;
      return kept == that.kept
          && ignoredBoolean == that.ignoredBoolean
          && Objects.equals(ignoredByGetter, that.ignoredByGetter)
          && Objects.equals(unsupportedWithIgnoredGetter, that.unsupportedWithIgnoredGetter);
    }

    @Override
    public int hashCode() {
      return Objects.hash(kept, ignoredByGetter, ignoredBoolean, unsupportedWithIgnoredGetter);
    }
  }

  @Test
  void testIgnoreOnGetter() {
    SerializingMutator<IgnoreOnGetterBean> mutator =
        (SerializingMutator<IgnoreOnGetterBean>)
            Mutators.newFactory()
                .createOrThrow(new TypeHolder<@NotNull IgnoreOnGetterBean>() {}.annotatedType());
    assertThat(mutator.toString()).startsWith("[Integer] -> IgnoreOnGetterBean");

    PseudoRandom prng = anyPseudoRandom();
    IgnoreOnGetterBean inited = mutator.init(prng);
    IgnoreOnGetterBean mutated = mutator.mutate(inited, prng);
    assertThat(mutated).isNotEqualTo(inited);
    assertThat(inited.ignoredByGetter).isNull();
    assertThat(mutated.ignoredByGetter).isNull();
    assertThat(inited.ignoredBoolean).isFalse();
    assertThat(mutated.ignoredBoolean).isFalse();
    assertThat(inited.unsupportedWithIgnoredGetter).isNull();
    assertThat(mutated.unsupportedWithIgnoredGetter).isNull();
  }

  static class AllIgnoredBean {
    private int foo;
    private String bar;

    public int getFoo() {
      return foo;
    }

    @JazzerIgnore
    public void setFoo(int foo) {
      this.foo = foo;
    }

    @JazzerIgnore
    public String getBar() {
      return bar;
    }

    public void setBar(String bar) {
      this.bar = bar;
    }
  }

  @Test
  void testAllIgnoredFallsBackToCachedConstructor() {
    assertThat(
            ChainedMutatorFactory.of(Stream.of(new SetterBasedBeanMutatorFactory()))
                .tryCreate(new TypeHolder<@NotNull AllIgnoredBean>() {}.annotatedType()))
        .isEmpty();

    SerializingMutator<AllIgnoredBean> mutator =
        (SerializingMutator<AllIgnoredBean>)
            Mutators.newFactory()
                .createOrThrow(new TypeHolder<@NotNull AllIgnoredBean>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("[] -> AllIgnoredBean");
  }

  static class MissingGetterWithAnotherIgnoredBean {
    private int missingGetter;
    private String ignored;

    public void setMissingGetter(int missingGetter) {
      this.missingGetter = missingGetter;
    }

    @JazzerIgnore
    public void setIgnored(String ignored) {
      this.ignored = ignored;
    }
  }

  @Test
  void testNonIgnoredSetterWithoutGetterStillFails() {
    assertThat(
            ChainedMutatorFactory.of(Stream.of(new SetterBasedBeanMutatorFactory()))
                .tryCreate(
                    new TypeHolder<
                        @NotNull MissingGetterWithAnotherIgnoredBean>() {}.annotatedType()))
        .isEmpty();
  }

  public static class IgnoreInheritedBeanParent {
    private int keptParent;
    private String ignoredParentSetter;
    private String ignoredParentGetter;

    public int getKeptParent() {
      return keptParent;
    }

    public void setKeptParent(int keptParent) {
      this.keptParent = keptParent;
    }

    public String getIgnoredParentSetter() {
      return ignoredParentSetter;
    }

    @JazzerIgnore
    public void setIgnoredParentSetter(String ignoredParentSetter) {
      this.ignoredParentSetter = ignoredParentSetter;
    }

    @JazzerIgnore
    public String getIgnoredParentGetter() {
      return ignoredParentGetter;
    }

    public void setIgnoredParentGetter(String ignoredParentGetter) {
      this.ignoredParentGetter = ignoredParentGetter;
    }
  }

  public static class IgnoreInheritedBeanChild extends IgnoreInheritedBeanParent {
    private int keptChild;

    public int getKeptChild() {
      return keptChild;
    }

    public void setKeptChild(int keptChild) {
      this.keptChild = keptChild;
    }
  }

  @Test
  void testIgnoreInherited() {
    SerializingMutator<IgnoreInheritedBeanChild> mutator =
        (SerializingMutator<IgnoreInheritedBeanChild>)
            Mutators.newFactory()
                .createOrThrow(
                    new TypeHolder<@NotNull IgnoreInheritedBeanChild>() {}.annotatedType());
    assertThat(mutator.toString()).startsWith("[Integer, Integer] -> IgnoreInheritedBeanChild");
  }
}
