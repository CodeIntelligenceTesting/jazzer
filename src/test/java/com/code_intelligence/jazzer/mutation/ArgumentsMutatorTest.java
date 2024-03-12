/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation;

import static com.code_intelligence.jazzer.mutation.support.TestSupport.mockPseudoRandom;
import static com.google.common.truth.Truth.assertThat;
import static java.util.Collections.singletonList;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.mutator.Mutators;
import com.code_intelligence.jazzer.mutation.support.TestSupport.MockPseudoRandom;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

@SuppressWarnings("OptionalGetWithoutIsPresent")
class ArgumentsMutatorTest {
  private static List<List<Boolean>> fuzzThisFunctionArgument1;
  private static List<Boolean> fuzzThisFunctionArgument2;

  public static void fuzzThisFunction(List<List<@NotNull Boolean>> list, List<Boolean> otherList) {
    fuzzThisFunctionArgument1 = list;
    fuzzThisFunctionArgument2 = otherList;
  }

  @Test
  @ResourceLock(value = "fuzzThisFunction")
  void testStaticMethod() throws Throwable {
    Method method =
        ArgumentsMutatorTest.class.getMethod("fuzzThisFunction", List.class, List.class);
    Optional<ArgumentsMutator> maybeMutator =
        ArgumentsMutator.forMethod(Mutators.newFactory(), method);
    assertThat(maybeMutator).isPresent();
    ArgumentsMutator mutator = maybeMutator.get();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // outer list not null
            false,
            // outer list size 1
            1,
            // inner list not null
            false,
            // inner list size 1
            1,
            // boolean
            true,
            // outer list not null
            false,
            // outer list size 1
            1,
            // Boolean not null
            false,
            // boolean
            false)) {
      mutator.init(prng);
    }

    fuzzThisFunctionArgument1 = null;
    fuzzThisFunctionArgument2 = null;
    mutator.invoke(this, true);
    assertThat(fuzzThisFunctionArgument1).containsExactly(singletonList(true));
    assertThat(fuzzThisFunctionArgument2).containsExactly(false);

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // mutate first argument
            0,
            // Nullable mutator
            false,
            // Action mutate in outer list
            2,
            // Mutate one element,
            1,
            // index to get to inner list
            0,
            // Nullable mutator
            false,
            // Action mutate inner list
            2,
            // Mutate one element,
            1,
            // index to get boolean value
            0)) {
      mutator.mutate(prng);
    }

    fuzzThisFunctionArgument1 = null;
    fuzzThisFunctionArgument2 = null;
    mutator.invoke(this, true);
    assertThat(fuzzThisFunctionArgument1).containsExactly(singletonList(false));
    assertThat(fuzzThisFunctionArgument2).containsExactly(false);

    // Modify the arguments passed to the function.
    fuzzThisFunctionArgument1.get(0).clear();
    fuzzThisFunctionArgument2.clear();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // mutate first argument
            0,
            // Nullable mutator
            false,
            // Action mutate in outer list
            2,
            // Mutate one element,
            1,
            // index to get to inner list
            0,
            // Nullable mutator
            false,
            // Action mutate inner list
            2,
            // Mutate one element,
            1,
            // index to get boolean value
            0)) {
      mutator.mutate(prng);
    }

    fuzzThisFunctionArgument1 = null;
    fuzzThisFunctionArgument2 = null;
    mutator.invoke(this, false);
    assertThat(fuzzThisFunctionArgument1).containsExactly(singletonList(true));
    assertThat(fuzzThisFunctionArgument2).containsExactly(false);
  }

  private List<List<Boolean>> mutableFuzzThisFunctionArgument1;
  private List<Boolean> mutableFuzzThisFunctionArgument2;

  public void mutableFuzzThisFunction(List<List<@NotNull Boolean>> list, List<Boolean> otherList) {
    mutableFuzzThisFunctionArgument1 = list;
    mutableFuzzThisFunctionArgument2 = otherList;
  }

  @Test
  void testInstanceMethod() throws Throwable {
    Method method =
        ArgumentsMutatorTest.class.getMethod("mutableFuzzThisFunction", List.class, List.class);
    Optional<ArgumentsMutator> maybeMutator =
        ArgumentsMutator.forMethod(Mutators.newFactory(), method);
    assertThat(maybeMutator).isPresent();
    ArgumentsMutator mutator = maybeMutator.get();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // outer list not null
            false,
            // outer list size 1
            1,
            // inner list not null
            false,
            // inner list size 1
            1,
            // boolean
            true,
            // outer list not null
            false,
            // outer list size 1
            1,
            // Boolean not null
            false,
            // boolean
            false)) {
      mutator.init(prng);
    }

    mutableFuzzThisFunctionArgument1 = null;
    mutableFuzzThisFunctionArgument2 = null;
    mutator.invoke(this, true);
    assertThat(mutableFuzzThisFunctionArgument1).containsExactly(singletonList(true));
    assertThat(mutableFuzzThisFunctionArgument2).containsExactly(false);

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // mutate first argument
            0,
            // Nullable mutator
            false,
            // Action mutate in outer list
            2,
            // Mutate one element,
            1,
            // index to get to inner list
            0,
            // Nullable mutator
            false,
            // Action mutate inner list
            2,
            // Mutate one element,
            1,
            // index to get boolean value
            0)) {
      mutator.mutate(prng);
    }

    mutableFuzzThisFunctionArgument1 = null;
    mutableFuzzThisFunctionArgument2 = null;
    mutator.invoke(this, true);
    assertThat(mutableFuzzThisFunctionArgument1).containsExactly(singletonList(false));
    assertThat(mutableFuzzThisFunctionArgument2).containsExactly(false);

    // Modify the arguments passed to the function.
    mutableFuzzThisFunctionArgument1.get(0).clear();
    mutableFuzzThisFunctionArgument2.clear();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // mutate first argument
            0,
            // Nullable mutator
            false,
            // Action mutate in outer list
            2,
            // Mutate one element,
            1,
            // index to get to inner list
            0,
            // Nullable mutator
            false,
            // Action mutate inner list
            2,
            // Mutate one element,
            1,
            // index to get boolean value
            0)) {
      mutator.mutate(prng);
    }

    mutableFuzzThisFunctionArgument1 = null;
    mutableFuzzThisFunctionArgument2 = null;
    mutator.invoke(this, false);
    assertThat(mutableFuzzThisFunctionArgument1).containsExactly(singletonList(true));
    assertThat(mutableFuzzThisFunctionArgument2).containsExactly(false);
  }

  @SuppressWarnings("unused")
  public void crossOverFunction(List<Boolean> list) {}

  @Test
  @SuppressWarnings("unchecked")
  void testCrossOver() throws Throwable {
    Method method = ArgumentsMutatorTest.class.getMethod("crossOverFunction", List.class);
    Optional<ArgumentsMutator> maybeMutator =
        ArgumentsMutator.forMethod(Mutators.newFactory(), method);
    assertThat(maybeMutator).isPresent();
    ArgumentsMutator mutator = maybeMutator.get();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // list not null
            false,
            // list size 1
            1,
            // not null,
            false,
            // boolean
            true)) {
      mutator.init(prng);
    }
    ByteArrayOutputStream baos1 = new ByteArrayOutputStream();
    mutator.write(baos1);
    byte[] out1 = baos1.toByteArray();

    try (MockPseudoRandom prng =
        mockPseudoRandom(
            // list not null
            false,
            // list size 1
            1,
            // not null
            false,
            // boolean
            false)) {
      mutator.init(prng);
    }
    ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
    mutator.write(baos2);
    byte[] out2 = baos1.toByteArray();

    mutator.crossOver(new ByteArrayInputStream(out1), new ByteArrayInputStream(out2), 12345);
    Object[] arguments = mutator.getArguments();

    assertThat(arguments).isNotEmpty();
    assertThat((List<Boolean>) arguments[0]).isNotEmpty();
  }
}
