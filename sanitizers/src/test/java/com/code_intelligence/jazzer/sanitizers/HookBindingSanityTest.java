/*
 * Copyright 2025 Code Intelligence GmbH
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
package com.code_intelligence.jazzer.sanitizers;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.code_intelligence.jazzer.api.MethodHook;
import com.code_intelligence.jazzer.api.MethodHooks;
import java.lang.invoke.MethodType;
import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Verifies that for every declared @MethodHook in built-in sanitizers, a corresponding target
 * method (or constructor) with the configured descriptor exists. This guards against typos and
 * wrong descriptors.
 */
public class HookBindingSanityTest {
  static class MethodRef {
    String className;
    String methodName;
    String descriptor;

    MethodRef(String className) {
      this.className = className;
    }

    MethodRef(String className, String methodName, String descriptor) {
      this.className = className;
      this.methodName = methodName;
      this.descriptor = descriptor;
    }

    @Override
    public int hashCode() {
      return Objects.hash(className, methodName, descriptor);
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof MethodRef)) return false;
      MethodRef other = (MethodRef) o;
      return Objects.equals(this.className, other.className)
          && Objects.equals(this.methodName, other.methodName)
          && Objects.equals(this.descriptor, other.descriptor);
    }
  }

  // Classes or methods that are not available in JDK version > 8.
  final Set<MethodRef> SKIPPED_CURRENT_JDK =
      Collections.unmodifiableSet(
          Stream.of(
                  new MethodRef("java.util.regex.Pattern$Single"),
                  new MethodRef("java.util.regex.Pattern$SingleI"),
                  new MethodRef("java.util.regex.Pattern$SingleS"),
                  new MethodRef("java.util.regex.Pattern$SingleU"),
                  new MethodRef(
                      "java.util.regex.Pattern",
                      "caseInsensitiveRangeFor",
                      "(II)Ljava/util/regex/Pattern$CharProperty;"),
                  new MethodRef(
                      "java.util.regex.Pattern",
                      "rangeFor",
                      "(II)Ljava/util/regex/Pattern$CharProperty;"),
                  new MethodRef(
                      "java.util.regex.Pattern",
                      "union",
                      "(Ljava/util/regex/Pattern$CharProperty;Ljava/util/regex/Pattern$CharProperty;)Ljava/util/regex/Pattern$CharProperty;"),
                  new MethodRef("sun.misc.Unsafe", "getByte", "(Ljava/lang/Object;I)B"),
                  new MethodRef("sun.misc.Unsafe", "getChar", "(Ljava/lang/Object;I)C"),
                  new MethodRef("sun.misc.Unsafe", "getDouble", "(Ljava/lang/Object;I)D"),
                  new MethodRef("sun.misc.Unsafe", "getFloat", "(Ljava/lang/Object;I)F"),
                  new MethodRef("sun.misc.Unsafe", "getInt", "(Ljava/lang/Object;I)I"),
                  new MethodRef("sun.misc.Unsafe", "getLong", "(Ljava/lang/Object;I)J"),
                  new MethodRef("sun.misc.Unsafe", "getShort", "(Ljava/lang/Object;I)S"),
                  new MethodRef("sun.misc.Unsafe", "putByte", "(Ljava/lang/Object;IB)V"),
                  new MethodRef("sun.misc.Unsafe", "putChar", "(Ljava/lang/Object;IC)V"),
                  new MethodRef("sun.misc.Unsafe", "putDouble", "(Ljava/lang/Object;ID)V"),
                  new MethodRef("sun.misc.Unsafe", "putFloat", "(Ljava/lang/Object;IF)V"),
                  new MethodRef("sun.misc.Unsafe", "putInt", "(Ljava/lang/Object;II)V"),
                  new MethodRef("sun.misc.Unsafe", "putLong", "(Ljava/lang/Object;IJ)V"),
                  new MethodRef("sun.misc.Unsafe", "putShort", "(Ljava/lang/Object;IS)V"))
              .collect(Collectors.toSet()));

  // Classes or methods that are not verified in JDK version 8.
  final Set<MethodRef> SKIPPED_JDK_8 =
      Collections.unmodifiableSet(
          Stream.of(
                  new MethodRef(
                      "org.springframework.expression.common.TemplateAwareExpressionParser"),
                  new MethodRef(
                      "org.springframework.expression.spel.standard.SpelExpressionParser"),
                  new MethodRef("jakarta.el.ExpressionFactory"),
                  new MethodRef("jakarta.el.ELProcessor"),
                  new MethodRef("java.util.regex.Pattern$CharPredicate"),
                  new MethodRef("javax.xml.xpath.XPath", "evaluateExpression", null),
                  new MethodRef(
                      "java.lang.Class",
                      "forName",
                      "(Ljava/lang/Module;Ljava/lang/String;)Ljava/lang/Class;"),
                  new MethodRef(
                      "java.lang.ClassLoader",
                      "loadClass",
                      "(Ljava/lang/Module;Ljava/lang/String;)Ljava/lang/Class;"),
                  new MethodRef("java.nio.file.Files", "mismatch", null),
                  new MethodRef("java.nio.file.Files", "readString", null),
                  new MethodRef("java.nio.file.Files", "writeString", null),
                  new MethodRef(
                      "java.util.regex.Pattern",
                      "CIRange",
                      "(II)Ljava/util/regex/Pattern$CharPredicate;"),
                  new MethodRef(
                      "java.util.regex.Pattern",
                      "CIRangeU",
                      "(II)Ljava/util/regex/Pattern$CharPredicate;"),
                  new MethodRef(
                      "java.util.regex.Pattern",
                      "Range",
                      "(II)Ljava/util/regex/Pattern$CharPredicate;"),
                  new MethodRef(
                      "java.util.regex.Pattern",
                      "Single",
                      "(I)Ljava/util/regex/Pattern$BmpCharPredicate;"),
                  new MethodRef(
                      "java.util.regex.Pattern",
                      "SingleI",
                      "(II)Ljava/util/regex/Pattern$BmpCharPredicate;"),
                  new MethodRef(
                      "java.util.regex.Pattern",
                      "SingleS",
                      "(I)Ljava/util/regex/Pattern$CharPredicate;"),
                  new MethodRef(
                      "java.util.regex.Pattern",
                      "SingleU",
                      "(I)Ljava/util/regex/Pattern$CharPredicate;"))
              .collect(Collectors.toSet()));

  final boolean isJDK8 = System.getProperty("java.version").startsWith("1.8");
  final Set<MethodRef> SKIPPED = isJDK8 ? SKIPPED_JDK_8 : SKIPPED_CURRENT_JDK;

  @ParameterizedTest
  @MethodSource("getMethodHooks")
  public void methodHookResolves(MethodHook hook) {
    String targetClassName = hook.targetClassName();
    assertNotNull(targetClassName, "Hook has no target class");
    if (SKIPPED.contains(new MethodRef(targetClassName))) {
      return;
    }
    ClassLoader loader = HookBindingSanityTest.class.getClassLoader();
    Class<?> targetClass =
        assertDoesNotThrow(
            () -> Class.forName(targetClassName, false, loader),
            () -> "class to hook not found: " + targetClassName);
    String methodName = hook.targetMethod();
    String methodDesc = hook.targetMethodDescriptor();
    methodDesc = (methodDesc != null && !methodDesc.isEmpty()) ? methodDesc : null;
    if (SKIPPED.contains(new MethodRef(targetClassName, methodName, methodDesc))) {
      return;
    }

    if ("<init>".equals(methodName)) {
      if (methodDesc == null) {
        // Any constructor is acceptable.
        assertNotEquals(
            0,
            targetClass.getDeclaredConstructors().length,
            String.format("no constructor for class %s found", targetClassName));
      } else {
        // Match specific constructor by descriptor
        MethodType mt = MethodType.fromMethodDescriptorString(methodDesc, loader);
        Class<?>[] descriptorParams = mt.parameterArray();
        assertTrue(
            Arrays.stream(targetClass.getDeclaredConstructors())
                .anyMatch(c -> Arrays.equals(c.getParameterTypes(), descriptorParams)),
            String.format("no matching constructor for class %s found", targetClassName));
      }
    } else {
      if (methodDesc == null) {
        // Require at least one declared method with that name
        assertTrue(
            Arrays.stream(targetClass.getDeclaredMethods())
                .anyMatch(md -> md.getName().equals(methodName)),
            String.format("method name %s not found in class %s", methodName, targetClassName));
      } else {
        MethodType mt = MethodType.fromMethodDescriptorString(methodDesc, loader);
        Class<?> descriptorReturnType = mt.returnType();
        Class<?>[] descriptorParams = mt.parameterArray();
        assertTrue(
            Arrays.stream(targetClass.getDeclaredMethods())
                .anyMatch(
                    md ->
                        md.getName().equals(methodName)
                            && md.getReturnType().equals(descriptorReturnType)
                            && Arrays.equals(md.getParameterTypes(), descriptorParams)),
            String.format(
                "method %s with descriptor %s not found in class %s",
                methodName, methodDesc, targetClassName));
      }
    }
  }

  static Class<?> getHookClass(String className) {
    try {
      return Class.forName(className, false, HookBindingSanityTest.class.getClassLoader());
    } catch (ClassNotFoundException e) {
      throw new RuntimeException("Could not find hook class " + className, e);
    }
  }

  static MethodHook[] getMethodHooks() {
    return Constants.SANITIZER_HOOK_NAMES.stream()
        .map(HookBindingSanityTest::getHookClass)
        .flatMap(clazz -> Stream.of(clazz.getMethods()))
        .flatMap(
            m ->
                Stream.concat(
                    Stream.of(m.getAnnotation(MethodHook.class)),
                    Optional.ofNullable(m.getAnnotation(MethodHooks.class))
                        .map(MethodHooks::value)
                        .map(Stream::of)
                        .orElseGet(Stream::empty)))
        .filter(Objects::nonNull)
        .toArray(MethodHook[]::new);
  }
}
