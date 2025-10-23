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

package com.example;

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;
import com.example.el.UserData;
import java.util.logging.Level;
import java.util.logging.LogManager;
import javax.el.ELException;
import javax.el.ELProcessor;
import javax.validation.Validation;
import javax.validation.Validator;
import org.junit.jupiter.api.BeforeEach;

public class ExpressionLanguageInjection {
  private static final Validator validator =
      Validation.buildDefaultValidatorFactory().getValidator();

  @BeforeEach
  public void setUp() {
    LogManager.getLogManager().getLogger("").setLevel(Level.SEVERE);
  }

  @FuzzTest
  void fuzzValidator(@NotNull String data) {
    UserData uncheckedUserData = new UserData(data);
    validator.validate(uncheckedUserData);
  }

  @FuzzTest
  void fuzzEval(@NotNull String data) {
    ELProcessor elp = new ELProcessor();
    try {
      elp.eval(data);
    } catch (ELException
        | IllegalStateException
        | IllegalArgumentException
        | ArithmeticException ignored) {
    }
  }
}
