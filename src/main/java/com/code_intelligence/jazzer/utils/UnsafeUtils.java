/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.utils;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandles.Lookup;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Optional;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

public final class UnsafeUtils {
  /**
   * Dynamically creates a concrete class implementing the given abstract class.
   *
   * <p>The returned class will not be functional and should only be used to construct instances via
   * {@link sun.misc.Unsafe#allocateInstance(Class)}.
   */
  public static <T> Class<? extends T> defineAnonymousConcreteSubclass(Class<T> abstractClass) {
    if (!Modifier.isAbstract(abstractClass.getModifiers())) {
      throw new IllegalArgumentException(abstractClass + " is not abstract");
    }

    ClassWriter cw = new ClassWriter(0);
    String superClassName = abstractClass.getName().replace('.', '/');
    // Only the package of the class name matters, the actual name is generated. defineHiddenClass
    // requires the package of the new class to match the one of the lookup.
    String className = UnsafeUtils.class.getPackage().getName().replace('.', '/') + "/Anonymous";
    cw.visit(Opcodes.V1_8, 0, className, null, superClassName, null);
    cw.visitEnd();

    try {
      Optional<Method> defineHiddenClass =
          Arrays.stream(Lookup.class.getMethods())
              .filter(method -> method.getName().equals("defineHiddenClass"))
              .findFirst();
      Optional<Class<?>> classOption =
          Arrays.stream(Lookup.class.getClasses())
              .filter(clazz -> clazz.getSimpleName().equals("ClassOption"))
              .findFirst();
      // MethodHandles.Lookup#defineHiddenClass is available as of Java 15.
      // Unsafe#defineAnonymousClass has been removed in Java 17.
      if (defineHiddenClass.isPresent() && classOption.isPresent()) {
        return ((MethodHandles.Lookup)
                defineHiddenClass
                    .get()
                    .invoke(
                        MethodHandles.lookup(),
                        cw.toByteArray(),
                        true,
                        Array.newInstance(classOption.get(), 0)))
            .lookupClass()
            .asSubclass(abstractClass);
      } else {
        return (Class<? extends T>)
            UnsafeProvider.getUnsafe()
                .getClass()
                .getMethod("defineAnonymousClass", Class.class, byte[].class, Object[].class)
                .invoke(UnsafeProvider.getUnsafe(), UnsafeUtils.class, cw.toByteArray(), null);
      }
    } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
      throw new IllegalStateException(e);
    }
  }

  private UnsafeUtils() {}
}
