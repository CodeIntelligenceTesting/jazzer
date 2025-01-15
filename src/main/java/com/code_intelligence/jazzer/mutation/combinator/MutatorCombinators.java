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

import static com.code_intelligence.jazzer.mutation.support.Preconditions.require;
import static com.code_intelligence.jazzer.mutation.support.Preconditions.requireNonNullElements;
import static java.util.Arrays.stream;
import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.joining;

import com.code_intelligence.jazzer.mutation.api.Debuggable;
import com.code_intelligence.jazzer.mutation.api.InPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.MutatorBase;
import com.code_intelligence.jazzer.mutation.api.PseudoRandom;
import com.code_intelligence.jazzer.mutation.api.Serializer;
import com.code_intelligence.jazzer.mutation.api.SerializingInPlaceMutator;
import com.code_intelligence.jazzer.mutation.api.SerializingMutator;
import com.code_intelligence.jazzer.mutation.support.Preconditions;
import com.google.errorprone.annotations.ImmutableTypeParameter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.function.ToIntFunction;
import net.jodah.typetools.TypeResolver;

public final class MutatorCombinators {
  // Inverse frequency in which value mutator should be used in cross over.
  private static final int INVERSE_PICK_VALUE_SUPPLIER_FREQUENCY = 100;

  private MutatorCombinators() {}

  public static <T, R> InPlaceMutator<T> mutateProperty(
      Function<T, R> getter, SerializingMutator<R> mutator, BiConsumer<T, R> setter) {
    requireNonNull(getter);
    requireNonNull(mutator);
    requireNonNull(setter);
    return new InPlaceMutator<T>() {
      @Override
      public void initInPlace(T reference, PseudoRandom prng) {
        setter.accept(reference, mutator.init(prng));
      }

      @Override
      public void mutateInPlace(T reference, PseudoRandom prng) {
        setter.accept(reference, mutator.mutate(getter.apply(reference), prng));
      }

      @Override
      public void crossOverInPlace(T reference, T otherReference, PseudoRandom prng) {
        // Most of the time cross over of properties should use one of the
        // given values and only seldom use the property type specific cross
        // over function. Other mutator combinators delegate to this one and
        // don't cross over values themselves.
        R referenceValue = getter.apply(reference);
        R otherReferenceValue = getter.apply(otherReference);
        R crossedOver =
            prng.pickValue(
                referenceValue,
                otherReferenceValue,
                () -> mutator.crossOver(referenceValue, otherReferenceValue, prng),
                INVERSE_PICK_VALUE_SUPPLIER_FREQUENCY);
        if (crossedOver == otherReferenceValue) {
          // If otherReference was picked, it needs to be detached as mutating
          // it is prohibited in cross over.
          crossedOver = mutator.detach(crossedOver);
        }
        setter.accept(reference, crossedOver);
      }

      @Override
      public boolean hasFixedSize() {
        return mutator.hasFixedSize();
      }

      @Override
      public String toDebugString(Predicate<Debuggable> isInCycle) {
        Class<?> owningType =
            TypeResolver.resolveRawArguments(Function.class, getter.getClass())[0];
        return owningType.getSimpleName() + "." + mutator.toDebugString(isInCycle);
      }

      @Override
      public String toString() {
        return Debuggable.getDebugString(this);
      }
    };
  }

  public static <T, R> InPlaceMutator<T> mutateViaView(
      Function<T, R> map, InPlaceMutator<R> mutator) {
    requireNonNull(map);
    requireNonNull(mutator);
    return new InPlaceMutator<T>() {
      @Override
      public void initInPlace(T reference, PseudoRandom prng) {
        mutator.initInPlace(map.apply(reference), prng);
      }

      @Override
      public void mutateInPlace(T reference, PseudoRandom prng) {
        mutator.mutateInPlace(map.apply(reference), prng);
      }

      @Override
      public void crossOverInPlace(T reference, T otherReference, PseudoRandom prng) {
        mutator.crossOverInPlace(map.apply(reference), map.apply(otherReference), prng);
      }

      @Override
      public boolean hasFixedSize() {
        return mutator.hasFixedSize();
      }

      @Override
      public String toDebugString(Predicate<Debuggable> isInCycle) {
        Class<?> owningType = TypeResolver.resolveRawArguments(Function.class, map.getClass())[0];
        return owningType.getSimpleName() + " via " + mutator.toDebugString(isInCycle);
      }

      @Override
      public String toString() {
        return Debuggable.getDebugString(this);
      }
    };
  }

  /**
   * Combines multiple in-place mutators for different parts of a {@code T} into one that picks one
   * at random whenever it mutates.
   *
   * <p>Calling this method with no arguments returns a no-op mutator that may decrease fuzzing
   * efficiency.
   */
  @SafeVarargs
  public static <T> InPlaceMutator<T> combine(InPlaceMutator<T>... partialMutators) {
    requireNonNullElements(partialMutators);
    if (partialMutators.length == 0) {
      return new InPlaceMutator<T>() {
        @Override
        public void initInPlace(T reference, PseudoRandom prng) {}

        @Override
        public void mutateInPlace(T reference, PseudoRandom prng) {}

        @Override
        public void crossOverInPlace(T reference, T otherReference, PseudoRandom prng) {}

        @Override
        public boolean hasFixedSize() {
          return true;
        }

        @Override
        public String toDebugString(Predicate<Debuggable> isInCycle) {
          return "{<empty>}";
        }

        @Override
        public String toString() {
          return Debuggable.getDebugString(this);
        }
      };
    }

    final InPlaceMutator<T>[] mutators = Arrays.copyOf(partialMutators, partialMutators.length);
    return new InPlaceMutator<T>() {
      private Boolean cachedHasFixedSize;

      @Override
      public void initInPlace(T reference, PseudoRandom prng) {
        for (InPlaceMutator<T> mutator : mutators) {
          mutator.initInPlace(reference, prng);
        }
      }

      @Override
      public void mutateInPlace(T reference, PseudoRandom prng) {
        mutators[prng.indexIn(mutators)].mutateInPlace(reference, prng);
      }

      @Override
      public void crossOverInPlace(T reference, T otherReference, PseudoRandom prng) {
        for (InPlaceMutator<T> mutator : mutators) {
          mutator.crossOverInPlace(reference, otherReference, prng);
        }
      }

      /** See comment on {@link SerializingMutator#hasFixedSize()}. */
      @Override
      public boolean hasFixedSize() {
        if (cachedHasFixedSize != null) {
          return cachedHasFixedSize;
        }
        cachedHasFixedSize = false;
        cachedHasFixedSize = stream(partialMutators).allMatch(InPlaceMutator::hasFixedSize);
        return cachedHasFixedSize;
      }

      @Override
      public String toDebugString(Predicate<Debuggable> isInCycle) {
        return stream(mutators)
            .map(mutator -> mutator.toDebugString(isInCycle))
            .collect(joining(", ", "{", "}"));
      }

      @Override
      public String toString() {
        return Debuggable.getDebugString(this);
      }
    };
  }

  public static <T, R> SerializingMutator<R> mutateThenMap(
      SerializingMutator<T> mutator, Function<T, R> map, Function<R, T> inverse) {
    return new PostComposedMutator<T, R>(mutator, map, inverse) {};
  }

  public static <T, R> SerializingMutator<R> mutateThenMap(
      SerializingMutator<T> mutator,
      Function<T, R> map,
      Function<R, T> inverse,
      Function<Predicate<Debuggable>, String> debug) {
    return new PostComposedMutator<T, R>(mutator, map, inverse) {
      @Override
      public String toDebugString(Predicate<Debuggable> isInCycle) {
        return debug.apply(isInCycle);
      }
    };
  }

  public static <T, R> SerializingMutator<R> mutateThenMap(
      Supplier<SerializingMutator<T>> mutator,
      Function<T, R> map,
      Function<R, T> inverse,
      BiFunction<SerializingMutator<T>, Predicate<Debuggable>, String> debug,
      Consumer<SerializingMutator<R>> registerSelf) {
    return new PostComposedMutator<T, R>(mutator, map, inverse, registerSelf) {
      @Override
      public String toDebugString(Predicate<Debuggable> isInCycle) {
        return debug.apply(this.mutator, isInCycle);
      }
    };
  }

  public static <T, @ImmutableTypeParameter R> SerializingMutator<R> mutateThenMapToImmutable(
      SerializingMutator<T> mutator, Function<T, R> map, Function<R, T> inverse) {
    return new PostComposedMutator<T, R>(mutator, map, inverse) {
      @Override
      public R detach(R value) {
        return value;
      }
    };
  }

  public static <T, @ImmutableTypeParameter R> SerializingMutator<R> mutateThenMapToImmutable(
      SerializingMutator<T> mutator,
      Function<T, R> map,
      Function<R, T> inverse,
      Function<Predicate<Debuggable>, String> debug) {
    return mutateThenMapToImmutable(
        () -> mutator, map, inverse, (unused, isInCycle) -> debug.apply(isInCycle), unused -> {});
  }

  public static <T, @ImmutableTypeParameter R> SerializingMutator<R> mutateThenMapToImmutable(
      Supplier<SerializingMutator<T>> mutator,
      Function<T, R> map,
      Function<R, T> inverse,
      BiFunction<SerializingMutator<T>, Predicate<Debuggable>, String> debug,
      Consumer<SerializingMutator<R>> registerSelf) {
    return new PostComposedMutator<T, R>(mutator, map, inverse, registerSelf) {
      @Override
      public R detach(R value) {
        return value;
      }

      @Override
      public String toDebugString(Predicate<Debuggable> isInCycle) {
        return debug.apply(this.mutator, isInCycle);
      }
    };
  }

  public static SerializingMutator<Integer> mutateIndices(int length) {
    require(length > 1, "There should be at least two indices to choose from");
    return new SerializingMutator<Integer>() {
      @Override
      public Integer read(DataInputStream in) throws IOException {
        return Math.floorMod(in.readInt(), length);
      }

      @Override
      public void write(Integer value, DataOutputStream out) throws IOException {
        out.writeInt(value);
      }

      @Override
      public Integer detach(Integer value) {
        return value;
      }

      @Override
      public Integer init(PseudoRandom prng) {
        return prng.closedRange(0, length - 1);
      }

      @Override
      public Integer mutate(Integer value, PseudoRandom prng) {
        return prng.otherIndexIn(length, value);
      }

      @Override
      public Integer crossOver(Integer value, Integer otherValue, PseudoRandom prng) {
        return prng.choice() ? value : otherValue;
      }

      @Override
      public boolean hasFixedSize() {
        return true;
      }

      @Override
      public String toDebugString(Predicate<Debuggable> isInCycle) {
        return "mutateIndices(" + length + ")";
      }
    };
  }

  /**
   * Combines multiple mutators for potentially different types into one that mutates an {@code
   * Object[]} containing one instance per mutator.
   */
  @SuppressWarnings("rawtypes")
  public static InPlaceProductMutator mutateProductInPlace(SerializingMutator... mutators) {
    return new InPlaceProductMutator(mutators);
  }

  @SuppressWarnings("rawtypes")
  public static ProductMutator mutateProduct(SerializingMutator... mutators) {
    return new ProductMutator(mutators);
  }

  /**
   * Mutates a sum type (e.g. a Protobuf oneof) in place, preferring to mutate the current state but
   * occasionally switching to a different state.
   *
   * @param getState a function that returns the current state of the sum type as an index into
   *     {@code perStateMutators}, or -1 if the state is indeterminate.
   * @param perStateMutators the mutators for each state
   * @return a mutator that mutates the sum type in place
   */
  @SafeVarargs
  public static <T> InPlaceMutator<T> mutateSumInPlace(
      ToIntFunction<T> getState, InPlaceMutator<T>... perStateMutators) {
    boolean hasFixedSize = stream(perStateMutators).allMatch(InPlaceMutator::hasFixedSize);
    final InPlaceMutator<T>[] mutators = Arrays.copyOf(perStateMutators, perStateMutators.length);
    return new InPlaceMutator<T>() {
      @Override
      public void initInPlace(T reference, PseudoRandom prng) {
        mutators[prng.indexIn(mutators)].initInPlace(reference, prng);
      }

      @Override
      public void mutateInPlace(T reference, PseudoRandom prng) {
        int currentState = getState.applyAsInt(reference);
        if (currentState == -1) {
          // The value is in an indeterminate state, initialize it.
          initInPlace(reference, prng);
        } else if (prng.trueInOneOutOf(100) && mutators.length > 1) {
          // Initialize to a different state.
          mutators[prng.otherIndexIn(mutators, currentState)].initInPlace(reference, prng);
        } else {
          // Mutate within the current state.
          mutators[currentState].mutateInPlace(reference, prng);
        }
      }

      @Override
      public void crossOverInPlace(T reference, T otherReference, PseudoRandom prng) {
        // Try to cross over in current state and leave state changes to the mutate step.
        int currentState = getState.applyAsInt(reference);
        int otherState = getState.applyAsInt(otherReference);
        if (currentState == -1) {
          // If reference is not initialized to a concrete state yet, try to do so in
          // the state of other reference, as that's at least some progress.
          if (otherState == -1) {
            // If both states are indeterminate, cross over can not be performed.
            return;
          }
          mutators[otherState].initInPlace(reference, prng);
        } else if (currentState == otherState) {
          mutators[currentState].crossOverInPlace(reference, otherReference, prng);
        }
      }

      @Override
      public boolean hasFixedSize() {
        return hasFixedSize;
      }

      @Override
      public String toDebugString(Predicate<Debuggable> isInCycle) {
        return stream(mutators)
            .map(mutator -> mutator.toDebugString(isInCycle))
            .collect(joining(" | "));
      }
    };
  }

  /**
   * Mutates a sum type (e.g. a sealed interface), preferring to mutate the current state but
   * occasionally switching to a different state.
   *
   * @param getState a function that returns the current state of the sum type as an index into
   *     {@code perStateMutators}, or -1 if the state is indeterminate.
   * @param perStateMutators the mutators for each state
   * @return a mutator that mutates the sum type
   */
  @SafeVarargs
  public static <T> SerializingMutator<?> mutateSum(
      ToIntFunction<T> getState, SerializingMutator<T>... perStateMutators) {
    Preconditions.require(perStateMutators.length > 0, "At least one mutator must be provided");
    if (perStateMutators.length == 1) {
      return perStateMutators[0];
    }
    boolean hasFixedSize = stream(perStateMutators).allMatch(SerializingMutator::hasFixedSize);
    final SerializingMutator<T>[] mutators =
        Arrays.copyOf(perStateMutators, perStateMutators.length);
    return new SerializingMutator<T>() {
      @Override
      public T init(PseudoRandom prng) {
        return mutators[prng.indexIn(mutators)].init(prng);
      }

      @Override
      public T mutate(T value, PseudoRandom prng) {
        int currentState = getState.applyAsInt(value);
        if (currentState == -1) {
          // The value is in an indeterminate state, initialize it.
          return init(prng);
        }
        if (prng.trueInOneOutOf(100)) {
          // Initialize to a different state.
          return mutators[prng.otherIndexIn(mutators, currentState)].init(prng);
        }
        // Mutate within the current state.
        return mutators[currentState].mutate(value, prng);
      }

      @Override
      public T crossOver(T value, T otherValue, PseudoRandom prng) {
        // Try to cross over in current state and leave state changes to the mutate step.
        int currentState = getState.applyAsInt(value);
        int otherState = getState.applyAsInt(otherValue);
        if (currentState == -1) {
          // If reference is not initialized to a concrete state yet, try to do so in
          // the state of other reference, as that's at least some progress.
          if (otherState == -1) {
            // If both states are indeterminate, cross over can not be performed.
            return value;
          }
          return mutators[otherState].init(prng);
        }
        if (currentState == otherState) {
          return mutators[currentState].crossOver(value, otherValue, prng);
        }
        return value;
      }

      @Override
      public T detach(T value) {
        int currentState = getState.applyAsInt(value);
        if (currentState == -1) {
          return value;
        }
        return mutators[currentState].detach(value);
      }

      @Override
      public T read(DataInputStream in) throws IOException {
        int currentState = Math.floorMod(in.readInt(), mutators.length);
        return mutators[currentState].read(in);
      }

      @Override
      public void write(T value, DataOutputStream out) throws IOException {
        int currentState = getState.applyAsInt(value);
        out.writeInt(currentState);
        mutators[currentState].write(value, out);
      }

      @Override
      public boolean hasFixedSize() {
        return hasFixedSize;
      }

      @Override
      public String toDebugString(Predicate<Debuggable> isInCycle) {
        return stream(mutators)
            .map(mutator -> mutator.toDebugString(isInCycle))
            .collect(joining(" | ", "(", ")"));
      }
    };
  }

  /**
   * Use {@link #markAsRequiringRecursionBreaking(SerializingMutator)} instead for {@link
   * com.code_intelligence.jazzer.mutation.api.ValueMutator}.
   *
   * @return a mutator that behaves identically to the provided one except that its {@link
   *     InPlaceMutator#initInPlace(Object, PseudoRandom)} is a no-op
   */
  public static <T> InPlaceMutator<T> withoutInit(InPlaceMutator<T> mutator) {
    return new InPlaceMutator<T>() {
      @Override
      public void initInPlace(T reference, PseudoRandom prng) {
        // Intentionally left empty.
      }

      @Override
      public String toDebugString(Predicate<Debuggable> isInCycle) {
        return "WithoutInit(" + mutator.toDebugString(isInCycle) + ")";
      }

      @Override
      public void mutateInPlace(T reference, PseudoRandom prng) {
        mutator.mutateInPlace(reference, prng);
      }

      @Override
      public void crossOverInPlace(T reference, T otherReference, PseudoRandom prng) {
        mutator.crossOverInPlace(reference, otherReference, prng);
      }

      @Override
      public boolean hasFixedSize() {
        return mutator.hasFixedSize();
      }
    };
  }

  /**
   * Preferably use {@link #withoutInit(InPlaceMutator)} instead for {@link InPlaceMutator}.
   *
   * @return a mutator that behaves identically to the provided one except that its {@link
   *     MutatorBase#requiresRecursionBreaking()} method returns {@code true}.
   */
  public static <T> SerializingMutator<T> markAsRequiringRecursionBreaking(
      SerializingMutator<T> mutator) {
    return new SerializingMutator<T>() {
      @Override
      public boolean requiresRecursionBreaking() {
        return true;
      }

      @Override
      public T init(PseudoRandom prng) {
        return mutator.init(prng);
      }

      @Override
      public String toDebugString(Predicate<Debuggable> isInCycle) {
        return "RecursionBreaking(" + mutator.toDebugString(isInCycle) + ")";
      }

      @Override
      public T read(DataInputStream in) throws IOException {
        return mutator.read(in);
      }

      @Override
      public void write(T value, DataOutputStream out) throws IOException {
        mutator.write(value, out);
      }

      @Override
      public T detach(T value) {
        return mutator.detach(value);
      }

      @Override
      public T mutate(T value, PseudoRandom prng) {
        return mutator.mutate(value, prng);
      }

      @Override
      public T crossOver(T value, T otherValue, PseudoRandom prng) {
        return mutator.crossOver(value, otherValue, prng);
      }

      @Override
      protected boolean computeHasFixedSize() {
        return mutator.hasFixedSize();
      }
    };
  }

  /**
   * Constructs a mutator that always returns the provided fixed value.
   *
   * <p>Note: This mutator explicitly breaks the contract of the init and mutate methods. Use
   * sparingly as it may harm the overall effectivity of the mutator.
   */
  public static <@ImmutableTypeParameter T> SerializingMutator<T> fixedValue(T value) {
    return new SerializingMutator<T>() {
      @Override
      public String toDebugString(Predicate<Debuggable> isInCycle) {
        return "FixedValue(" + value + ")";
      }

      @Override
      public T read(DataInputStream in) {
        return value;
      }

      @Override
      public void write(T value, DataOutputStream out) {}

      @Override
      public T detach(T value) {
        return value;
      }

      @Override
      public T init(PseudoRandom prng) {
        return value;
      }

      @Override
      public T mutate(T value, PseudoRandom prng) {
        return value;
      }

      @Override
      public T crossOver(T value, T otherValue, PseudoRandom prng) {
        return value;
      }

      @Override
      public boolean hasFixedSize() {
        return true;
      }
    };
  }

  /**
   * Assembles the parameters into a full implementation of {@link SerializingInPlaceMutator<T>}:
   *
   * @param registerSelf a callback that will receive the uninitialized mutator instance before
   *     {@code lazyMutator} is invoked. For simple cases this can just do nothing, but it is needed
   *     to implement mutators for structures that are self-referential (e.g. Protobuf message A
   *     having a field of type A).
   * @param makeDefaultInstance constructs a mutable default instance of {@code T}
   * @param serializer implementation of the {@link Serializer<T>} part
   * @param lazyMutator supplies the implementation of the {@link InPlaceMutator<T>} part. This is
   *     guaranteed to be invoked exactly once and only after {@code registerSelf}.
   */
  public static <T> SerializingInPlaceMutator<T> assemble(
      Consumer<SerializingInPlaceMutator<T>> registerSelf,
      Supplier<T> makeDefaultInstance,
      Serializer<T> serializer,
      Supplier<InPlaceMutator<T>> lazyMutator) {
    return new DelegatingSerializingInPlaceMutator<>(
        registerSelf, makeDefaultInstance, serializer, lazyMutator);
  }

  private static final class DelegatingSerializingInPlaceMutator<T>
      extends SerializingInPlaceMutator<T> {
    private final Supplier<T> makeDefaultInstance;
    private final Serializer<T> serializer;
    private final InPlaceMutator<T> mutator;

    private DelegatingSerializingInPlaceMutator(
        Consumer<SerializingInPlaceMutator<T>> registerSelf,
        Supplier<T> makeDefaultInstance,
        Serializer<T> serializer,
        Supplier<InPlaceMutator<T>> lazyMutator) {
      requireNonNull(makeDefaultInstance);
      requireNonNull(serializer);

      registerSelf.accept(this);
      this.makeDefaultInstance = makeDefaultInstance;
      this.serializer = serializer;
      this.mutator = lazyMutator.get();
    }

    @Override
    public void initInPlace(T reference, PseudoRandom prng) {
      mutator.initInPlace(reference, prng);
    }

    @Override
    public void mutateInPlace(T reference, PseudoRandom prng) {
      mutator.mutateInPlace(reference, prng);
    }

    @Override
    public void crossOverInPlace(T reference, T otherReference, PseudoRandom prng) {
      mutator.crossOverInPlace(reference, otherReference, prng);
    }

    @Override
    protected boolean computeHasFixedSize() {
      return mutator.hasFixedSize();
    }

    @Override
    protected T makeDefaultInstance() {
      return makeDefaultInstance.get();
    }

    @Override
    public T read(DataInputStream in) throws IOException {
      return serializer.read(in);
    }

    @Override
    public void write(T value, DataOutputStream out) throws IOException {
      serializer.write(value, out);
    }

    @Override
    public T readExclusive(InputStream in) throws IOException {
      return serializer.readExclusive(in);
    }

    @Override
    public void writeExclusive(T value, OutputStream out) throws IOException {
      serializer.writeExclusive(value, out);
    }

    @Override
    public T detach(T value) {
      return serializer.detach(value);
    }

    @Override
    public String toDebugString(Predicate<Debuggable> isInCycle) {
      if (isInCycle.test(this)) {
        return "(cycle)";
      } else {
        return mutator.toDebugString(isInCycle);
      }
    }
  }
}
