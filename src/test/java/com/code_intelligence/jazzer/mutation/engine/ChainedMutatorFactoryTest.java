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
