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
import org.apache.commons.jexl2.Expression;
import org.apache.commons.jexl2.JexlContext;
import org.apache.commons.jexl2.JexlEngine;
import org.apache.commons.jexl2.JexlException;
import org.apache.commons.jexl2.MapContext;
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

  @FuzzTest
  void fuzzJexlExpression(@NotNull String data) {
    JexlEngine jexl = new JexlEngine();
    JexlContext context = new MapContext();

    try {
      Expression expr = jexl.createExpression(data);
      expr.evaluate(context);
    } catch (JexlException | StringIndexOutOfBoundsException ignored) {
    }
  }
}
