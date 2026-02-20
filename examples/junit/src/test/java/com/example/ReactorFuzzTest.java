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

public class ReactorFuzzTest {

  @FuzzTest
  public void fuzz(@NotNull String input) {
    for (char c : input.toCharArray()) {
      if (c < 32 || c > 126) return;
    }
    controlReactor(input);
  }

  private void controlReactor(String commands) {
    long temperature = 0; // Starts cold

    for (char cmd : commands.toCharArray()) {
      // Complex, chaotic feedback loop.
      // It is hard to predict which character increases temperature
      // because it depends on the CURRENT temperature.
      if ((temperature ^ cmd) % 3 == 0) {
        temperature += (cmd % 10); // Heat up slightly
      } else if ((temperature ^ cmd) % 3 == 1) {
        temperature -= (cmd % 8); // Cool down slightly
      } else {
        temperature += 1; // Tiny increase
      }

      // Prevent dropping below absolute zero for simulation sanity
      if (temperature < 0) temperature = 0;
    }
    // THE GOAL: MAXIMIZATION
    // We need to drive 'temperature' to an extreme value.
    // Standard coverage is 100% constant here (it just loops).
    Jazzer.maximize(temperature, 0, 4500);
    if (temperature >= 4500) {
      throw new RuntimeException("Meltdown! Temperature maximized.");
    }
  }
}
