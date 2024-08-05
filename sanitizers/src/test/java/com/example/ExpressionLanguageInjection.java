/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.example.el.UserData;
import java.util.logging.Level;
import java.util.logging.LogManager;
import javax.validation.Validation;
import javax.validation.Validator;

public class ExpressionLanguageInjection {
  private static final Validator validator =
      Validation.buildDefaultValidatorFactory().getValidator();

  public static void fuzzerInitialize() {
    LogManager.getLogManager().getLogger("").setLevel(Level.SEVERE);
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    UserData uncheckedUserData = new UserData(data.consumeRemainingAsString());
    validator.validate(uncheckedUserData);
  }
}
