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

package com.code_intelligence.jazzer.driver;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Optional;

class ReflectionUtils {
  static Optional<Method> targetPublicStaticMethod(
      Class<?> clazz, String name, Class<?>... parameterTypes) {
    try {
      Method method = clazz.getMethod(name, parameterTypes);
      if (!Modifier.isStatic(method.getModifiers()) || !Modifier.isPublic(method.getModifiers())) {
        return Optional.empty();
      }
      return Optional.of(method);
    } catch (NoSuchMethodException e) {
      return Optional.empty();
    }
  }
}
