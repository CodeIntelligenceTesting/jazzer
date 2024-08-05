/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example.el;

import static java.lang.String.format;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class InsecureEmailValidator implements ConstraintValidator<ValidEmailConstraint, String> {
  @Override
  public void initialize(ValidEmailConstraint email) {}

  @Override
  public boolean isValid(String email, ConstraintValidatorContext cxt) {
    if (email == null || !email.matches(".+@.+\\..+")) {
      // Insecure: do not call buildConstraintViolationWithTemplate with untrusted data!
      cxt.buildConstraintViolationWithTemplate(format("Invalid email address: %s", email))
          .addConstraintViolation();
      return false;
    }
    return true;
  }
}
