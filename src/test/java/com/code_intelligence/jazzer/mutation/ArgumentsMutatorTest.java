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

  public static class EmptyBeanWithRuntimeError {
    static boolean throwInConstructor = false;

    public EmptyBeanWithRuntimeError() {
      if (throwInConstructor) throw new RuntimeException("Runtime error in constructor");
    }

    public static void throwErrorInConstructor(boolean val) {
      throwInConstructor = val;
    }
  }

  public void readEmptyBeanWithRuntimeError(@NotNull EmptyBeanWithRuntimeError data) {}

  @Test
  void testReadEmptyBeanWithRuntimeError() throws NoSuchMethodException {
    Method method =
        ArgumentsMutatorTest.class.getMethod(
            "readEmptyBeanWithRuntimeError", EmptyBeanWithRuntimeError.class);
    Optional<ArgumentsMutator> maybeMutator =
        ArgumentsMutator.forMethod(Mutators.newFactory(), method);
    assertThat(maybeMutator).isPresent();
    ArgumentsMutator mutator = maybeMutator.get();

    mutator.init(12345);
    Object[] arguments = mutator.getArguments();
    assertThat(arguments).isNotEmpty();
    assertThat(arguments[0]).isInstanceOf(EmptyBeanWithRuntimeError.class);

    // @NotNull EmptyBean should be read without error.
    mutator.read(new ByteArrayInputStream(new byte[1]));
    arguments = mutator.getArguments();
    assertThat(arguments).isNotEmpty();
    assertThat(arguments[0]).isInstanceOf(EmptyBeanWithRuntimeError.class);

    // Error in constructor results in a finding---the user should fix the fuzz test or
    // fuzz with JAZZER_KEEP_GOING.
    EmptyBeanWithRuntimeError.throwErrorInConstructor(true);
    try {
      mutator.read(new ByteArrayInputStream(new byte[1]));
    } catch (RuntimeException e) {
      // expected
    }
  }
}
