// Copyright 2021 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import javax.validation.*;

class UserData {
  public UserData(String email) {
    this.email = email;
  }

  @ValidEmailConstraint private String email;
}

@Constraint(validatedBy = InsecureEmailValidator.class)
@Target({ElementType.METHOD, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@interface ValidEmailConstraint {
  String message() default "Invalid email address";
  Class<?>[] groups() default {};
  Class<? extends Payload>[] payload() default {};
}

public class ExpressionLanguageInjection {
  final private static Validator validator =
      Validation.buildDefaultValidatorFactory().getValidator();

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    UserData uncheckedUserData = new UserData(data.consumeRemainingAsString());
    validator.validate(uncheckedUserData);
  }
}
