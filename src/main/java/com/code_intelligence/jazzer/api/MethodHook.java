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

package com.code_intelligence.jazzer.api;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.invoke.MethodType;

/**
 * Registers the annotated method as a hook that should run before, instead or after the method
 * specified by the annotation parameters.
 *
 * <p>Depending on {@link #type()} this method will be called after, instead or before every call to
 * the target method and has access to its parameters and return value. The target method is
 * specified by {@link #targetClassName()} and {@link #targetMethod()}. In case of an overloaded
 * method, {@link #targetMethodDescriptor()} can be used to restrict the application of the hook to
 * a particular overload.
 *
 * <p>The signature of the annotated method must be as follows (this does not restrict the method
 * name and parameter names, which are arbitrary), depending on the value of {@link #type()}:
 *
 * <dl>
 *   <dt><span class="strong">{@link HookType#BEFORE}</span>
 *   <dd>
 *       <pre>{@code
 * public static void hook(MethodHandle method, Object thisObject, Object[] arguments, int hookId)
 * }</pre>
 *       Arguments:
 *       <p>
 *       <ul>
 *         <li>{@code method}: A {@link java.lang.invoke.MethodHandle} representing the original
 *             method. The original method can be invoked via {@link
 *             java.lang.invoke.MethodHandle#invokeWithArguments(Object...)}. This requires passing
 *             {@code thisObject} as the first argument if the method is not static. This argument
 *             can be {@code null}.
 *         <li>{@code thisObject}: An {@link Object} containing the implicit {@code this} argument
 *             to the original method. If the original method is static, this argument will be
 *             {@code null}.
 *         <li>{@code arguments}: An array of {@link Object}s containing the arguments passed to the
 *             original method. Primitive types (e.g. {@code boolean}) will be wrapped into their
 *             corresponding wrapper type (e.g. {@link Boolean}).
 *         <li>{@code hookId}: A random {@code int} identifying the particular call site.This can be
 *             used to derive additional coverage information.
 *       </ul>
 *   <dt><span class="strong">{@link HookType#REPLACE}</span>
 *   <dd>
 *       <pre>{@code
 * public static Object hook(MethodHandle method, Object thisObject, Object[] arguments, int hookId)
 * }</pre>
 *       The return type may alternatively be taken to be the exact return type of target method or
 *       a wrapper type thereof. The returned object will be casted and unwrapped automatically.
 *       <p>Arguments:
 *       <p>
 *       <ul>
 *         <li>{@code method}: A {@link java.lang.invoke.MethodHandle} representing the original
 *             method. The original method can be invoked via {@link
 *             java.lang.invoke.MethodHandle#invokeWithArguments(Object...)}. This requires passing
 *             {@code thisObject} as the first argument if the method is not static. This argument
 *             can be {@code null}.
 *         <li>{@code thisObject}: An {@link Object} containing the implicit {@code this} argument
 *             to the original method. If the original method is static, this argument will be
 *             {@code null}.
 *         <li>{@code arguments}: An array of {@link Object}s containing the arguments passed to the
 *             original method. Primitive types (e.g. {@code boolean}) will be wrapped into their
 *             corresponding wrapper type (e.g. {@link Boolean}).
 *         <li>{@code hookId}: A random {@code int} identifying the particular call site.This can be
 *             used to derive additional coverage information.
 *       </ul>
 *       <p>
 *       <p>Return value: the value that should take the role of the value the target method would
 *       have returned
 *       <p>
 *   <dt><span class="strong">{@link HookType#AFTER}</span>
 *   <dd>
 *       <pre>{@code
 * public static void hook(MethodHandle method, Object thisObject, Object[] arguments, int hookId,
 * Object returnValue)
 * }</pre>
 *       Arguments:
 *       <p>
 *       <ul>
 *         <li>{@code method}: A {@link java.lang.invoke.MethodHandle} representing the original
 *             method. The original method can be invoked via {@link
 *             java.lang.invoke.MethodHandle#invokeWithArguments(Object...)}. This requires passing
 *             {@code thisObject} as the first argument if the method is not static. This argument
 *             can be {@code null}.
 *         <li>{@code thisObject}: An {@link Object} containing the implicit {@code this} argument
 *             to the original method. If the original method is static, this argument will be
 *             {@code null}.
 *         <li>{@code arguments}: An array of {@link Object}s containing the arguments passed to the
 *             original method. Primitive types (e.g. {@code boolean}) will be wrapped into their
 *             corresponding wrapper type (e.g. {@link Boolean}).
 *         <li>{@code hookId}: A random {@code int} identifying the particular call site.This can be
 *             used to derive additional coverage information.
 *         <li>{@code returnValue}: An {@link Object} containing the return value of the invocation
 *             of the original method. Primitive types (e.g. {@code boolean}) will be wrapped into
 *             their corresponding wrapper type (e.g. {@link Boolean}). If the original method has
 *             return type {@code void}, this value will be {@code null}.
 *             <p>Multiple {@link HookType#BEFORE} and {@link HookType#AFTER} hooks are allowed to
 *             reference the same target method. Exclusively one {@link HookType#REPLACE} hook may
 *             reference a target method, no other types allowed. Attention must be paid to not
 *             guide the Fuzzer in different directions via {@link Jazzer}'s {@code guideTowardsXY}
 *             methods in the different hooks.
 *       </ul>
 * </dl>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@Repeatable(MethodHooks.class)
@Documented
public @interface MethodHook {
  /**
   * The time at which the annotated method should be called.
   *
   * <p>If this is {@link HookType#BEFORE}, the annotated method will be called before the target
   * method and has access to its arguments.
   *
   * <p>If this is {@link HookType#REPLACE}, the annotated method will be called instead of the
   * target method. It has access to its arguments and can return a value that will replace the
   * target method's return value.
   *
   * <p>If this is {@link HookType#AFTER}, the annotated method will be called after the target
   * method and has access to its arguments and return value.
   *
   * @return when the hook should be called
   */
  HookType type();

  /**
   * The name of the class that contains the method that should be hooked, as returned by {@link
   * Class#getName()}.
   *
   * <p>If an interface or abstract class is specified, also calls to all implementations and
   * subclasses available on the classpath during startup are hooked, respectively. Interfaces and
   * subclasses are not taken into account for concrete classes.
   *
   * <p>Examples:
   *
   * <p>
   *
   * <ul>
   *   <li>{@link String}: {@code "java.lang.String"}
   *   <li>{@link java.nio.file.FileSystem}: {@code "java.nio.file.FileSystem"}
   * </ul>
   *
   * <p>
   *
   * @return the name of the class containing the method to be hooked
   */
  String targetClassName();

  /**
   * The name of the method to be hooked. Use {@code "<init>"} for constructors.
   *
   * <p>Examples:
   *
   * <p>
   *
   * <ul>
   *   <li>{@link String#equals(Object)}: {@code "equals"}
   *   <li>{@link String#String()}: {@code "<init>"}
   * </ul>
   *
   * <p>
   *
   * @return the name of the method to be hooked
   */
  String targetMethod();

  /**
   * The descriptor of the method to be hooked. This is only needed if there are multiple methods
   * with the same name and not all of them should be hooked.
   *
   * <p>The descriptor of a method is an internal representation of the method's signature, which
   * includes the types of its parameters and its return value. For more information on descriptors,
   * see the <a href=https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.3.3>JVM
   * Specification, Section 4.3.3</a> and {@link MethodType#toMethodDescriptorString()}
   *
   * @return the descriptor of the method to be hooked
   */
  String targetMethodDescriptor() default "";

  /**
   * Array of additional classes to hook.
   *
   * <p>Hooks are applied on call sites. This means that classes calling the one defined in this
   * annotation need to be instrumented to actually execute the hook. This property can be used to
   * hook normally ignored classes.
   *
   * @return fully qualified class names to hook
   */
  String[] additionalClassesToHook() default {};
}
