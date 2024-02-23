/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.code_intelligence.jazzer.mutation.annotation.proto;

import static java.lang.annotation.ElementType.TYPE_USE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import com.code_intelligence.jazzer.mutation.utils.AppliesTo;
import com.google.protobuf.DynamicMessage;
import com.google.protobuf.Message;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * Provides a default instance to use as the base for mutations of the annotated {@link Message} or
 * {@link DynamicMessage.Builder}.
 */
@Target(TYPE_USE)
@Retention(RUNTIME)
@AppliesTo(subClassesOf = {Message.class, Message.Builder.class})
public @interface WithDefaultInstance {
  /**
   * The fully qualified name of a static method (e.g. {@code
   * com.example.MyClass#getDefaultInstance}) with return type assignable to {@link
   * com.google.protobuf.Message}, which returns a default instance that mutations should be based
   * on.
   */
  String value();
}
