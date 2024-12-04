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
