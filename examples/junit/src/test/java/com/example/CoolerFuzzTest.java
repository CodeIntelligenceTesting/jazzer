/*
 * Copyright 2026 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example;

import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;

/**
 * Example demonstrating the minimize() hill-climbing API.
 *
 * <p>Mirror of ReactorFuzzTest: instead of heating up a reactor, we're trying to cool down a system
 * to the lowest possible temperature.
 */
public class CoolerFuzzTest {

  @FuzzTest
  public void fuzz(@NotNull String input) {
    for (char c : input.toCharArray()) {
      if (c < 32 || c > 126) return;
    }
    controlCooler(input);
  }

  private void controlCooler(String commands) {
    long temperature = 4000; // Starts hot

    for (char cmd : commands.toCharArray()) {
      // Complex, chaotic feedback loop.
      // Hard to predict which character decreases temperature.
      if ((temperature ^ cmd) % 3 == 0) {
        temperature -= (cmd % 10); // Cool down slightly
      } else if ((temperature ^ cmd) % 3 == 1) {
        temperature += (cmd % 8); // Heat up slightly
      } else {
        temperature -= 1; // Tiny decrease
      }

      // Cap at reasonable bounds
      if (temperature < 0) temperature = 0;
      if (temperature > 5000) temperature = 5000;
    }

    // THE GOAL: MINIMIZATION
    // Drive 'temperature' to the lowest possible value.
    Jazzer.minimize(temperature, 0, 4000);
    if (temperature <= 100) {
      throw new RuntimeException("Supercooled! Temperature minimized.");
    }
  }
}
