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

package com.code_intelligence.jazzer.autofuzz;

import io.github.classgraph.ClassInfo;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Comparator;
import java.util.stream.Stream;

class AccessibleObjectLookup {
  private static final Comparator<Class<?>> STABLE_CLASS_COMPARATOR =
      Comparator.comparing(Class::getName);
  private static final Comparator<Executable> STABLE_EXECUTABLE_COMPARATOR =
      Comparator.comparing(Executable::getName)
          .thenComparing(
              executable -> {
                if (executable instanceof Method) {
                  return org.objectweb.asm.Type.getMethodDescriptor((Method) executable);
                } else {
                  return org.objectweb.asm.Type.getConstructorDescriptor(
                      (Constructor<?>) executable);
                }
              });

  private final Class<?> referenceClass;

  public AccessibleObjectLookup(Class<?> referenceClass) {
    this.referenceClass = referenceClass;
  }

  Class<?>[] getAccessibleClasses(Class<?> type) {
    return Stream.concat(Arrays.stream(type.getDeclaredClasses()), Arrays.stream(type.getClasses()))
        .distinct()
        .filter(this::isAccessible)
        .sorted(STABLE_CLASS_COMPARATOR)
        .toArray(Class<?>[]::new);
  }

  Constructor<?>[] getAccessibleConstructors(Class<?> type) {
    // Neither of getDeclaredConstructors and getConstructors is a superset of the other: While
    // getDeclaredConstructors returns constructors with all visibility modifiers, it does not
    // return the implicit default constructor.
    return Stream.concat(
            Arrays.stream(type.getDeclaredConstructors()), Arrays.stream(type.getConstructors()))
        .distinct()
        .filter(this::isAccessible)
        .sorted(STABLE_EXECUTABLE_COMPARATOR)
        .filter(
            constructor -> {
              try {
                constructor.setAccessible(true);
                return true;
              } catch (Exception e) {
                // Can't make the constructor accessible, e.g. because it is in a standard library
                // module. We can't do anything about this, so we skip the constructor.
                return false;
              }
            })
        .toArray(Constructor<?>[]::new);
  }

  Method[] getAccessibleMethods(Class<?> type) {
    return Stream.concat(Arrays.stream(type.getDeclaredMethods()), Arrays.stream(type.getMethods()))
        .distinct()
        .filter(this::isAccessible)
        .sorted(STABLE_EXECUTABLE_COMPARATOR)
        .filter(
            method -> {
              try {
                method.setAccessible(true);
                return true;
              } catch (Exception e) {
                // Can't make the method accessible, e.g. because it is in a standard library
                // module. We
                // can't do anything about this, so we skip the method.
                return false;
              }
            })
        .toArray(Method[]::new);
  }

  boolean isAccessible(Class<?> clazz, int modifiers) {
    if (Modifier.isPublic(modifiers)) {
      return true;
    }
    if (referenceClass == null) {
      return false;
    }
    if (Modifier.isPrivate(modifiers)) {
      return clazz.equals(referenceClass);
    }
    if (Modifier.isProtected(modifiers)) {
      return clazz.isAssignableFrom(referenceClass);
    }
    // No visibility modifiers implies default visibility, which means visible in the same package.
    return clazz.getPackage().equals(referenceClass.getPackage());
  }

  boolean isAccessible(ClassInfo clazz, int modifiers) {
    if (Modifier.isPublic(modifiers)) {
      return true;
    }
    if (referenceClass == null) {
      return false;
    }
    if (Modifier.isPrivate(modifiers)) {
      return clazz.getName().equals(referenceClass.getName());
    }
    if (Modifier.isProtected(modifiers)) {
      return isAssignableFrom(clazz, referenceClass);
    }
    // No visibility modifiers implies default visibility, which means visible in the same package.
    return clazz.getPackageName().equals(referenceClass.getPackage().getName());
  }

  boolean isAssignableFrom(ClassInfo clazz, Class<?> potentialSubclass) {
    if (potentialSubclass.getName().equals(clazz.getName())) {
      return true;
    }
    if (potentialSubclass.equals(Object.class)) {
      return clazz.getName().equals(Object.class.getName());
    }
    if (potentialSubclass.getSuperclass() == null) {
      return false;
    }
    return isAssignableFrom(clazz, potentialSubclass.getSuperclass());
  }

  private boolean isAccessible(Executable executable) {
    return isAccessible(executable.getDeclaringClass(), executable.getModifiers());
  }

  private boolean isAccessible(Class<?> clazz) {
    return isAccessible(clazz, clazz.getModifiers());
  }
}
