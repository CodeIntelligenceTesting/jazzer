/*
 * Copyright 2025 Code Intelligence GmbH
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

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public final class ObjectInputStreamFuzzer {

  public static void fuzzerTestOneInput(byte[] data) {
    try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
      Object o = ois.readObject();
      Class<?> clazz = o.getClass();
      clazz.getTypeName();
      clazz.getMethods();
      clazz.getRecordComponents();
      clazz.getDeclaredFields();
      clazz.getDeclaredMethods();
      clazz.getDeclaredConstructors();
      clazz.getAnnotations();
      clazz.getDeclaredAnnotations();
      clazz.getInterfaces();
      clazz.getGenericInterfaces();
      clazz.getGenericSuperclass();
      clazz.getNestHost();
      clazz.getNestMembers();
      clazz.getPermittedSubclasses();
      clazz.getModule();
      touchFields(clazz.getFields());
      touchFields(clazz.getDeclaredFields());
      touchMethods(clazz.getMethods());
      touchMethods(clazz.getDeclaredMethods());
      touchConstructors(clazz.getDeclaredConstructors());
      for (Class<?> nested : clazz.getDeclaredClasses()) {
        nested.getTypeName();
      }
    } catch (Throwable ignored) {
    }
  }

  private static void touchFields(Field[] fields) {
    for (Field field : fields) {
      field.getName();
      field.getType();
      field.getGenericType();
      field.getAnnotations();
      field.getDeclaringClass();
    }
  }

  private static void touchMethods(Method[] methods) {
    for (Method method : methods) {
      method.getName();
      method.getParameterTypes();
      method.getGenericParameterTypes();
      method.getReturnType();
      method.getGenericReturnType();
      method.getExceptionTypes();
      method.getAnnotations();
      method.getParameters();
    }
  }

  private static void touchConstructors(Constructor<?>[] constructors) {
    for (Constructor<?> constructor : constructors) {
      constructor.getName();
      constructor.getParameterTypes();
      constructor.getGenericParameterTypes();
      constructor.getExceptionTypes();
      constructor.getDeclaredAnnotations();
    }
  }
}
