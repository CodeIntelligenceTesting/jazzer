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

package com.code_intelligence.jazzer.mutation.support;

import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static com.code_intelligence.jazzer.mutation.support.Preconditions.requireNonNullElements;
import static com.google.common.truth.Truth.assertThat;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toCollection;
import static java.util.stream.Collectors.toList;

import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.api.InPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.engine.SeededPseudoRandom;
import com.google.errorprone.annotations.CheckReturnValue;
import com.google.errorprone.annotations.MustBeClosed;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Queue;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

public final class TestSupport {
  private static final DataOutputStream nullDataOutputStream =
      new DataOutputStream(
          new OutputStream() {
            @Override
            public void write(int i) {}
          });

  private TestSupport() {}

  public static DataOutputStream nullDataOutputStream() {
    return nullDataOutputStream;
  }

  /**
   * Deterministically creates a new instance of {@link PseudoRandom} whose exact behavior is
   * intentionally unspecified.
   */
  // TODO: Turn usages of this function into fuzz tests.
  public static PseudoRandom anyPseudoRandom() {
    // Change this seed from time to time to shake out tests relying on hardcoded behavior.
    return new SeededPseudoRandom(8853461259049838337L);
  }

  /** Creates a {@link PseudoRandom} whose methods return the given values in order. */
  @MustBeClosed
  public static MockPseudoRandom mockPseudoRandom(Object... returnValues) {
    return new MockPseudoRandom(returnValues);
  }

  @CheckReturnValue
  public static <T> SerializingMutator<T> mockMutator(T initialValue, UnaryOperator<T> mutate) {
    return mockMutator(initialValue, mutate, value -> value);
  }

  @CheckReturnValue
  public static <T> SerializingMutator<T> mockMutator(
      T initialValue, UnaryOperator<T> mutate, UnaryOperator<T> detach) {
    return new AbstractMockMutator<T>() {
      @Override
      protected T nextInitialValue() {
        return initialValue;
      }

      @Override
      public T mutate(T value, PseudoRandom prng) {
        return mutate.apply(value);
      }

      @Override
      public T detach(T value) {
        return detach.apply(value);
      }
    };
  }

  @CheckReturnValue
  public static <T> SerializingMutator<T> mockInitializer(
      Supplier<T> getInitialValues, UnaryOperator<T> detach) {
    return new AbstractMockMutator<T>() {
      @Override
      protected T nextInitialValue() {
        return getInitialValues.get();
      }

      @Override
      public T mutate(T value, PseudoRandom prng) {
        throw new UnsupportedOperationException();
      }

      @Override
      public T detach(T value) {
        return detach.apply(value);
      }
    };
  }

  @CheckReturnValue
  public static <T> SerializingMutator<T> mockCrossOver(BiFunction<T, T, T> getCrossOverValue) {
    return new AbstractMockMutator<T>() {
      @Override
      protected T nextInitialValue() {
        throw new UnsupportedOperationException();
      }

      @Override
      public T mutate(T value, PseudoRandom prng) {
        throw new UnsupportedOperationException();
      }

      @Override
      public T crossOver(T value, T otherValue, PseudoRandom prng) {
        return getCrossOverValue.apply(value, otherValue);
      }

      @Override
      public T detach(T value) {
        return value;
      }
    };
  }

  @CheckReturnValue
  public static <T> InPlaceMutator<T> mockCrossOverInPlace(BiConsumer<T, T> crossOverInPlace) {
    return new AbstractMockInPlaceMutator<T>() {
      @Override
      public void crossOverInPlace(T reference, T otherReference, PseudoRandom prng) {
        crossOverInPlace.accept(reference, otherReference);
      }

      @Override
      public String toDebugString(Predicate<Debuggable> isInCycle) {
        return "CrossOverInPlaceMockMutator";
      }
    };
  }

  @CheckReturnValue
  public static <T> InPlaceMutator<T> mockInitInPlace(Consumer<T> setInitialValues) {
    return new AbstractMockInPlaceMutator<T>() {
      @Override
      public void initInPlace(T reference, PseudoRandom prng) {
        setInitialValues.accept(reference);
      }

      @Override
      public String toDebugString(Predicate<Debuggable> isInCycle) {
        return "InitInPlaceMockMutator";
      }
    };
  }

  private abstract static class AbstractMockInPlaceMutator<T> implements InPlaceMutator<T> {
    @Override
    public void initInPlace(T reference, PseudoRandom prng) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void mutateInPlace(T reference, PseudoRandom prng) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void crossOverInPlace(T reference, T otherReference, PseudoRandom prng) {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean hasFixedSize() {
      // This value is ignored by MockPseudoRandom.
      return false;
    }
  }

  private abstract static class AbstractMockMutator<T> extends SerializingMutator<T> {
    protected abstract T nextInitialValue();

    @Override
    public T read(DataInputStream in) {
      return nextInitialValue();
    }

    @Override
    public void write(T value, DataOutputStream out) {
      throw new UnsupportedOperationException("mockMutator does not support write");
    }

    @Override
    public T init(PseudoRandom prng) {
      return nextInitialValue();
    }

    @Override
    public T crossOver(T value, T otherValue, PseudoRandom prng) {
      return value;
    }

    @Override
    public boolean hasFixedSize() {
      // This value is ignored by MockPseudoRandom.
      return false;
    }

    @Override
    public String toDebugString(Predicate<Debuggable> isInCycle) {
      T initialValue = nextInitialValue();
      if (initialValue == null) {
        return "null";
      }
      return initialValue.getClass().getSimpleName();
    }

    @Override
    public T detach(T value) {
      return value;
    }
  }

  public static final class MockPseudoRandom implements PseudoRandom, AutoCloseable {
    private final Queue<Object> elements;

    private MockPseudoRandom(Object... objects) {
      requireNonNullElements(objects);
      this.elements = stream(objects).collect(toCollection(ArrayDeque::new));
    }

    public String toString() {
      return "PRNG: " + Arrays.toString(elements.toArray());
    }

    @Override
    public boolean choice() {
      assertThat(elements).isNotEmpty();
      return (boolean) elements.poll();
    }

    @Override
    public boolean trueInOneOutOf(int inverseFrequencyTrue) {
      assertThat(inverseFrequencyTrue).isAtLeast(2);

      assertThat(elements).isNotEmpty();
      return (boolean) elements.poll();
    }

    @Override
    public <T> T pickIn(T[] array) {
      assertThat(array).isNotEmpty();

      assertThat(elements).isNotEmpty();
      return array[(int) elements.poll()];
    }

    @Override
    public <T> T pickIn(List<T> list) {
      assertThat(list).isNotEmpty();

      assertThat(elements).isNotEmpty();
      return list.get((int) elements.poll());
    }

    @Override
    public <T> int indexIn(T[] array) {
      return indexIn(array.length);
    }

    @Override
    public <T> int indexIn(List<T> list) {
      return indexIn(list.size());
    }

    @Override
    public int indexIn(int range) {
      assertThat(range).isAtLeast(1);

      assertThat(elements).isNotEmpty();
      int result = (int) elements.poll();
      assertThat(result).isAtLeast(0);
      assertThat(result).isLessThan(range);
      return result;
    }

    @Override
    public <T> int otherIndexIn(T[] array, int currentIndex) {
      return otherIndexIn(array.length, currentIndex);
    }

    @Override
    public int otherIndexIn(int range, int currentValue) {
      assertThat(range).isAtLeast(2);
      assertThat(elements).isNotEmpty();
      int result = (int) elements.poll();
      assertThat(result).isAtLeast(0);
      assertThat(result).isAtMost(range - 1);
      assertThat(result).isNotEqualTo(currentValue);
      return result;
    }

    @Override
    public int closedRange(int lowerInclusive, int upperInclusive) {
      assertThat(lowerInclusive).isAtMost(upperInclusive);

      assertThat(elements).isNotEmpty();
      int result = (int) elements.poll();
      assertThat(result).isAtLeast(lowerInclusive);
      assertThat(result).isAtMost(upperInclusive);
      return result;
    }

    @Override
    public long closedRange(long lowerInclusive, long upperInclusive) {
      assertThat(lowerInclusive).isAtMost(upperInclusive);

      assertThat(elements).isNotEmpty();
      long result = (long) elements.poll();
      assertThat(result).isAtLeast(lowerInclusive);
      assertThat(result).isAtMost(upperInclusive);
      return result;
    }

    @Override
    public float closedRange(float lowerInclusive, float upperInclusive) {
      assertThat(lowerInclusive).isLessThan(upperInclusive);
      assertThat(elements).isNotEmpty();
      float result = (float) elements.poll();
      assertThat(result).isAtLeast(lowerInclusive);
      assertThat(result).isAtMost(upperInclusive);
      return result;
    }

    @Override
    public double closedRange(double lowerInclusive, double upperInclusive) {
      assertThat(lowerInclusive).isLessThan(upperInclusive);
      assertThat(elements).isNotEmpty();
      double result = (double) elements.poll();
      assertThat(result).isAtLeast(lowerInclusive);
      assertThat(result).isAtMost(upperInclusive);
      return result;
    }

    @Override
    public int sizeInClosedRange(
        int lowerInclusive, int upperInclusive, boolean elementsHaveFixedSize) {
      assertThat(lowerInclusive).isAtMost(upperInclusive);

      assertThat(elements).isNotEmpty();
      int result = (int) elements.poll();
      assertThat(result).isAtLeast(lowerInclusive);
      assertThat(result).isAtMost(upperInclusive);
      return result;
    }

    @Override
    public void bytes(byte[] bytes) {
      assertThat(elements).isNotEmpty();
      byte[] result = (byte[]) elements.poll();
      assertThat(result).hasLength(bytes.length);
      System.arraycopy(result, 0, bytes, 0, bytes.length);
    }

    @Override
    public <T> T pickValue(
        T value, T otherValue, Supplier<T> supplier, int inverseSupplierFrequency) {
      assertThat(elements).isNotEmpty();
      switch ((int) elements.poll()) {
        case 0:
          return value;
        case 1:
          return otherValue;
        case 2:
          return supplier.get();
        default:
          throw new AssertionError("Invalid pickValue element");
      }
    }

    @Override
    public long nextLong() {
      assertThat(elements).isNotEmpty();
      return (long) elements.poll();
    }

    @Override
    public void close() {
      assertThat(elements).isEmpty();
    }
  }

  @SuppressWarnings("unchecked")
  public static <K, V> LinkedHashMap<K, V> asMap(Object... objs) {
    LinkedHashMap<K, V> map = new LinkedHashMap<>();
    for (int i = 0; i < objs.length; i += 2) {
      map.put((K) objs[i], (V) objs[i + 1]);
    }
    return map;
  }

  @SafeVarargs
  public static <T> ArrayList<T> asMutableList(T... objs) {
    return stream(objs).collect(toCollection(ArrayList::new));
  }

  /**
   * A factory for {@link AnnotatedType} instances capturing method parameters.
   *
   * <p>Due to type erasure, this class can only be used by creating an anonymous subclass with a
   * method called {@code singleParam} that takes exactly the desired parameter.
   *
   * <p>Example: {@code new ParameterHolder {void singleParam(@NotNull List<String> param)}
   * .annotatedType}
   */
  public abstract static class ParameterHolder {
    protected ParameterHolder() {}

    public AnnotatedType annotatedType() {
      return getMethod().getAnnotatedParameterTypes()[0];
    }

    public Type type() {
      return annotatedType().getType();
    }

    public Annotation[] parameterAnnotations() {
      return getMethod().getParameterAnnotations()[0];
    }

    private Method getMethod() {
      List<Method> methods =
          stream(this.getClass().getDeclaredMethods())
              .filter(method -> method.getName().equals("singleParam"))
              .collect(toList());
      require(
          methods.size() == 1,
          this.getClass().getName() + " must define exactly one function named 'singleParam'");
      Method foo = methods.get(0);
      require(
          foo.getParameterCount() == 1,
          this.getClass().getName() + "#singleParam must define exactly one parameter");
      return foo;
    }
  }

  public static <T> SerializingMutator<T> createOrThrow(
      ExtendedMutatorFactory factory, TypeHolder<T> typeHolder) {
    return (SerializingMutator<T>) factory.createOrThrow(typeHolder.annotatedType());
  }
}
