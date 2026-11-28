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

import com.code_intelligence.jazzer.mutation.annotation.IgnoreGetters;
import com.code_intelligence.jazzer.mutation.annotation.IgnoreProperties;
import com.code_intelligence.jazzer.mutation.annotation.IgnoreSetters;
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

  static class PlainBeanWithIgnoredMembers {
    private int kept;
    private String ignoredBySetter;
    private String ignoredByGetter;
    private boolean ignoredBoolean;
    private Object unsupportedWriteOnly;
    private Object unsupportedWithGetter;

    public int getKept() {
      return kept;
    }

    public void setKept(int kept) {
      this.kept = kept;
    }

    public String getIgnoredBySetter() {
      return ignoredBySetter;
    }

    public void setIgnoredBySetter(String ignoredBySetter) {
      this.ignoredBySetter = ignoredBySetter;
    }

    public String getIgnoredByGetter() {
      return ignoredByGetter;
    }

    public void setIgnoredByGetter(String ignoredByGetter) {
      this.ignoredByGetter = ignoredByGetter;
    }

    public boolean isIgnoredBoolean() {
      return ignoredBoolean;
    }

    public void setIgnoredBoolean(boolean ignoredBoolean) {
      this.ignoredBoolean = ignoredBoolean;
    }

    public void setUnsupportedWriteOnly(Object unsupportedWriteOnly) {
      this.unsupportedWriteOnly = unsupportedWriteOnly;
    }

    public Object getUnsupportedWithGetter() {
      return unsupportedWithGetter;
    }

    public void setUnsupportedWithGetter(Object unsupportedWithGetter) {
      this.unsupportedWithGetter = unsupportedWithGetter;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      PlainBeanWithIgnoredMembers that = (PlainBeanWithIgnoredMembers) o;
      return kept == that.kept
          && ignoredBoolean == that.ignoredBoolean
          && Objects.equals(ignoredBySetter, that.ignoredBySetter)
          && Objects.equals(ignoredByGetter, that.ignoredByGetter)
          && Objects.equals(unsupportedWriteOnly, that.unsupportedWriteOnly)
          && Objects.equals(unsupportedWithGetter, that.unsupportedWithGetter);
    }

    @Override
    public int hashCode() {
      return Objects.hash(
          kept,
          ignoredBySetter,
          ignoredByGetter,
          ignoredBoolean,
          unsupportedWriteOnly,
          unsupportedWithGetter);
    }
  }

  @Test
  void testIgnoreSettersAndGettersCombined() {
    SerializingMutator<PlainBeanWithIgnoredMembers> mutator =
        (SerializingMutator<PlainBeanWithIgnoredMembers>)
            Mutators.newFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull @IgnoreSetters({"setIgnoredBySetter", "setUnsupportedWriteOnly"})
                        @IgnoreGetters({
                          "getIgnoredByGetter", "isIgnoredBoolean", "getUnsupportedWithGetter"
                        })
                        PlainBeanWithIgnoredMembers>() {}.annotatedType());
    assertThat(mutator.toString()).startsWith("[Integer] -> PlainBeanWithIgnoredMembers");

    PseudoRandom prng = anyPseudoRandom();
    PlainBeanWithIgnoredMembers inited = mutator.init(prng);
    PlainBeanWithIgnoredMembers mutated = mutator.mutate(inited, prng);
    assertThat(mutated).isNotEqualTo(inited);
    assertThat(inited.ignoredBySetter).isNull();
    assertThat(mutated.ignoredBySetter).isNull();
    assertThat(inited.ignoredByGetter).isNull();
    assertThat(mutated.ignoredByGetter).isNull();
    assertThat(inited.ignoredBoolean).isFalse();
    assertThat(mutated.ignoredBoolean).isFalse();
    assertThat(inited.unsupportedWriteOnly).isNull();
    assertThat(mutated.unsupportedWriteOnly).isNull();
    assertThat(inited.unsupportedWithGetter).isNull();
    assertThat(mutated.unsupportedWithGetter).isNull();
  }

  @Test
  void testIgnorePropertiesByName() {
    SerializingMutator<PlainBeanWithIgnoredMembers> mutator =
        (SerializingMutator<PlainBeanWithIgnoredMembers>)
            Mutators.newFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull
                        @IgnoreProperties({
                          "ignoredBySetter",
                          "ignoredByGetter",
                          "ignoredBoolean",
                          "unsupportedWriteOnly",
                          "unsupportedWithGetter"
                        })
                        PlainBeanWithIgnoredMembers>() {}.annotatedType());
    assertThat(mutator.toString()).startsWith("[Integer] -> PlainBeanWithIgnoredMembers");
  }

  static class AllIgnoredBean {
    private int foo;
    private String bar;

    public int getFoo() {
      return foo;
    }

    public void setFoo(int foo) {
      this.foo = foo;
    }

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
                .tryCreate(
                    new TypeHolder<
                        @NotNull @IgnoreSetters("setFoo") @IgnoreGetters("getBar")
                        AllIgnoredBean>() {}.annotatedType()))
        .isEmpty();

    SerializingMutator<AllIgnoredBean> mutator =
        (SerializingMutator<AllIgnoredBean>)
            Mutators.newFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull @IgnoreProperties({"foo", "bar"})
                        AllIgnoredBean>() {}.annotatedType());
    assertThat(mutator.toString()).isEqualTo("[] -> AllIgnoredBean");
  }

  static class MissingGetterWithAnotherIgnoredBean {
    private int missingGetter;
    private String ignored;

    public void setMissingGetter(int missingGetter) {
      this.missingGetter = missingGetter;
    }

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
                        @NotNull @IgnoreSetters("setIgnored")
                        MissingGetterWithAnotherIgnoredBean>() {}.annotatedType()))
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

    public void setIgnoredParentSetter(String ignoredParentSetter) {
      this.ignoredParentSetter = ignoredParentSetter;
    }

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
                    new TypeHolder<
                        @NotNull @IgnoreSetters("setIgnoredParentSetter")
                        @IgnoreGetters("getIgnoredParentGetter")
                        IgnoreInheritedBeanChild>() {}.annotatedType());
    assertThat(mutator.toString()).startsWith("[Integer, Integer] -> IgnoreInheritedBeanChild");
  }

  static class Jwks {
    // No default constructor: unsupported by SetterBasedBeanMutatorFactory /
    // CachedConstructorMutatorFactory.
    private Jwks(String raw) {}
  }

  static class SubJwks extends Jwks {
    private SubJwks(String raw) {
      super(raw);
    }
  }

  static class App {
    private String name;
    private Jwks jwks;
    private SubJwks subJwks;
    private List<Jwks> jwksList;
    private Jwks[] jwksArray;

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public Jwks getJwks() {
      return jwks;
    }

    public void setJwks(Jwks jwks) {
      this.jwks = jwks;
    }

    public SubJwks getSubJwks() {
      return subJwks;
    }

    public void setSubJwks(SubJwks subJwks) {
      this.subJwks = subJwks;
    }

    public List<Jwks> getJwksList() {
      return jwksList;
    }

    public void setJwksList(List<Jwks> jwksList) {
      this.jwksList = jwksList;
    }

    public Jwks[] getJwksArray() {
      return jwksArray;
    }

    public void setJwksArray(Jwks[] jwksArray) {
      this.jwksArray = jwksArray;
    }
  }

  static class OnboardingBean {
    private int id;
    private App app;

    public int getId() {
      return id;
    }

    public void setId(int id) {
      this.id = id;
    }

    public App getApp() {
      return app;
    }

    public void setApp(App app) {
      this.app = app;
    }
  }

  @Test
  void testIgnorePropertiesByTypeRecursively() {
    SerializingMutator<OnboardingBean> mutator =
        (SerializingMutator<OnboardingBean>)
            Mutators.newFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull @IgnoreProperties(types = Jwks.class)
                        OnboardingBean>() {}.annotatedType());
    assertThat(mutator.toString())
        .isEqualTo("[Nullable<[Nullable<String>] -> App>, Integer] -> OnboardingBean");

    PseudoRandom prng = anyPseudoRandom();
    OnboardingBean inited = mutator.init(prng);
    OnboardingBean mutated = mutator.mutate(inited, prng);
    assertThat(mutated).isNotNull();
    if (mutated.getApp() != null) {
      assertThat(mutated.getApp().getJwks()).isNull();
      assertThat(mutated.getApp().getSubJwks()).isNull();
      assertThat(mutated.getApp().getJwksList()).isNull();
      assertThat(mutated.getApp().getJwksArray()).isNull();
    }
  }

  @Test
  void testIgnorePropertiesDeclarationScopeDoesNotPropagateToNestedBeans() {
    assertThat(
            Mutators.newFactory()
                .tryCreate(
                    new TypeHolder<
                        @NotNull
                        @IgnoreProperties(
                            types = Jwks.class,
                            constraint = PropertyConstraint.DECLARATION)
                        OnboardingBean>() {}.annotatedType()))
        .isEmpty();
  }

  @Test
  void testIgnorePropertiesOnRecursiveTypeBean() {
    SerializingMutator<RecursiveTypeBean> mutator =
        (SerializingMutator<RecursiveTypeBean>)
            Mutators.newFactory()
                .createOrThrow(
                    new TypeHolder<
                        @NotNull @IgnoreProperties("foo") RecursiveTypeBean>() {}.annotatedType());
    assertThat(mutator.toString())
        .isEqualTo(
            "[Nullable<RecursionBreaking((cycle) -> RecursiveTypeBean)>] -> RecursiveTypeBean");
  }
}
