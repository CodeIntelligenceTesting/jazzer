/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.engine;

import static com.code_intelligence.jazzer.utils.CapturedOutput.withCapturedOutput;
import static com.google.common.truth.Truth.assertThat;

import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.code_intelligence.jazzer.mutation.api.ExtendedMutatorFactory;
import com.code_intelligence.jazzer.mutation.mutator.Mutators;
import com.code_intelligence.jazzer.mutation.support.TypeHolder;
import com.code_intelligence.jazzer.utils.CapturedOutput.Output;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

public class ChainedMutatorFactoryTest {

  @Test
  @SuppressWarnings("ResultOfMethodCallIgnored")
  public void printErrorMessagesOnFailedCreate() {
    Output output =
        withCapturedOutput(
            () -> {
              ExtendedMutatorFactory factory = Mutators.newFactory();
              factory.tryCreate(
                  new TypeHolder<List<Map<@NotNull String, System>>>() {}.annotatedType());
            });

    assertThat(output.err)
        .contains("java.util.List<java.util.Map<java.lang.String, java.lang.System>>");
    assertThat(output.err).contains("java.util.Map<java.lang.String, java.lang.System>");
    assertThat(output.err).contains("java.lang.System <<< ERROR");
  }
}
