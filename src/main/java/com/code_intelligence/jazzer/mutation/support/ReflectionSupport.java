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

package com.code_intelligence.jazzer.mutation.support;

import static java.util.Arrays.stream;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

public final class ReflectionSupport {

  private ReflectionSupport() {}

  public static MethodHandle unreflectNewInstance(
      MethodHandles.Lookup lookup, Executable newInstance) {
    Preconditions.check(
        newInstance instanceof Constructor || Modifier.isStatic(newInstance.getModifiers()),
        String.format(
            "New instance method %s must be a static method or a constructor", newInstance));
    Preconditions.check(
        newInstance.getAnnotatedReturnType().getType() != Void.class,
        String.format("Return type of %s must not be void", newInstance));
    newInstance.setAccessible(true);
    try {
      if (newInstance instanceof Method) {
        return lookup.unreflect((Method) newInstance);
      } else {
        return lookup.unreflectConstructor((Constructor<?>) newInstance);
      }
    } catch (IllegalAccessException e) {
      throw new RuntimeException(e);
    }
  }

  public static MethodHandle[] unreflectMethods(MethodHandles.Lookup lookup, Method... methods) {
    return stream(methods)
        .map(method -> unreflectMethod(lookup, method))
        .toArray(MethodHandle[]::new);
  }

  public static MethodHandle unreflectMethod(MethodHandles.Lookup lookup, Method method) {
    try {
      method.setAccessible(true);
      return lookup.unreflect(method);
    } catch (IllegalAccessException e) {
      throw new RuntimeException(e);
    }
  }
}
