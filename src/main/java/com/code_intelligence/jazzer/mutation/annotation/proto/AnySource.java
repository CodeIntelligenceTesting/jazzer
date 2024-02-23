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
import com.google.protobuf.Message;
import com.google.protobuf.Message.Builder;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * Controls the mutations of {@link com.google.protobuf.Any} fields in messages of the annotated
 * type as well as its recursive message fields.
 */
@Target(TYPE_USE)
@Retention(RUNTIME)
@AppliesTo(subClassesOf = {Message.class, Builder.class})
public @interface AnySource {
  /** A non-empty list of {@link Message}s to use for {@link com.google.protobuf.Any} fields. */
  Class<? extends Message>[] value();
}
