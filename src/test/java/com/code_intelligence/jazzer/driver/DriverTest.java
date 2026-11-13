/*
 * Copyright 2026 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.driver;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

public class DriverTest {
  private static List<String> translate(long exitOnTime, long exitOnTimeMinRuns, String... args) {
    List<String> result = new ArrayList<>(Arrays.asList(args));
    Driver.translateExitOnTimeOptions(result, exitOnTime, exitOnTimeMinRuns);
    return result;
  }

  @Test
  void exitOnTimeWithMinRuns() {
    assertThat(translate(2, 1, "--exit_on_time=2", "--exit_on_time_min_runs=1"))
        .containsExactly("-exit_on_time=2", "-exit_on_time_min_runs=1")
        .inOrder();
  }

  @Test
  void exitOnTimeWithDefaultMinRuns() {
    assertThat(translate(2, 100000, "--exit_on_time=2"))
        .containsExactly("-exit_on_time=2", "-exit_on_time_min_runs=100000")
        .inOrder();
  }

  @Test
  void onlyMinRunsIsNotForwarded() {
    assertThat(translate(0, 5, "--exit_on_time_min_runs=5")).isEmpty();
  }

  @Test
  void explicitZeroIsNotForwarded() {
    assertThat(translate(0, 5, "--exit_on_time=0", "--exit_on_time_min_runs=5")).isEmpty();
  }

  @Test
  void nativeFlagsTakePrecedence() {
    assertThat(
            translate(
                100,
                5,
                "--exit_on_time=100",
                "-exit_on_time=2",
                "--exit_on_time_min_runs=5",
                "-exit_on_time_min_runs=7"))
        .containsExactly("-exit_on_time=2", "-exit_on_time_min_runs=7")
        .inOrder();
  }

  @Test
  void unrelatedArgsArePreserved() {
    assertThat(translate(0, 100000, "-runs=10", "--target_class=Foo"))
        .containsExactly("-runs=10", "--target_class=Foo")
        .inOrder();
  }

  @Test
  void valuesExceedingIntRangeAreRejected() {
    assertThrows(
        IllegalArgumentException.class,
        () -> translate((long) Integer.MAX_VALUE + 1, 1, "--exit_on_time=2147483648"));
    assertThrows(
        IllegalArgumentException.class,
        () -> translate(1, (long) Integer.MAX_VALUE + 1, "--exit_on_time=1"));
    // Values parsed as unsigned 64-bit integers may appear negative as signed longs.
    assertThrows(IllegalArgumentException.class, () -> translate(-1, 1));
    assertThat(translate(Integer.MAX_VALUE, Integer.MAX_VALUE))
        .containsExactly("-exit_on_time=2147483647", "-exit_on_time_min_runs=2147483647")
        .inOrder();
  }
}
