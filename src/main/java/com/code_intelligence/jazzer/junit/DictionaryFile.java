package com.code_intelligence.jazzer.junit;

import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Defines a reference to a dictionary within the resources directory. These should follow <a
 * href="https://llvm.org/docs/LibFuzzer.html#dictionaries">libfuzzer's dictionary syntax</a>.
 */
@Target({ElementType.METHOD, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Repeatable(DictionaryFiles.class)
public @interface DictionaryFile {
    String resourcePath();
}

