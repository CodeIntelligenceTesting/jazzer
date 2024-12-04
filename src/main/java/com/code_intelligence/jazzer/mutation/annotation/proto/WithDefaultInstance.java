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
