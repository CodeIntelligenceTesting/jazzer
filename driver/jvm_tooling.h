/*
 * Copyright 2021 Code Intelligence GmbH
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

#pragma once

#include <jni.h>

#include <string>

namespace jazzer {

void DumpJvmStackTraces();

// JVM is a thin wrapper around JNI_CreateJavaVM and DestroyJavaVM. The JVM
// instance is created inside the constructor with some default JNI options
// + options which can be added to via command line flags.
class JVM {
 private:
  JavaVM *jvm_;
  JNIEnv *env_;

 public:
  // Creates a JVM instance with default options + options that were provided as
  // command line flags.
  explicit JVM(std::string_view executable_path, std::string_view seed);

  // Destroy the running JVM instance.
  ~JVM();

  // Get the JNI environment for interaction with the running JVM instance.
  JNIEnv &GetEnv() const;

  jclass FindClass(std::string class_name) const;
  jmethodID GetStaticMethodID(jclass class_id, const std::string &method_name,
                              const std::string &signature,
                              bool is_required = true) const;
  jmethodID GetMethodID(jclass class_id, const std::string &method_name,
                        const std::string &signature) const;
  jfieldID GetStaticFieldID(jclass jclass, const std::string &field_name,
                            const std::string &type) const;
};

// Adds convenience methods to convert a jvm exception to std::string
// using StringWriter and PrintWriter. The stack trace can be subjected to
// further processing, such as deduplication token computation and severity
// annotation.
class ExceptionPrinter {
 private:
  const JVM &jvm_;

  jclass string_writer_class_;
  jmethodID string_writer_constructor_;
  jmethodID string_writer_to_string_method_;

  jclass print_writer_class_;
  jmethodID print_writer_constructor_;
  jmethodID print_stack_trace_method_;

  jclass exception_utils_;
  jmethodID compute_dedup_token_method_;
  jmethodID preprocess_throwable_method_;

 protected:
  explicit ExceptionPrinter(JVM &jvm);

  // returns the current JVM exception stack trace as a string
  std::string getStackTrace(jthrowable exception) const;
  // augments the throwable with additional information such as severity markers
  jthrowable preprocessException(jthrowable exception) const;
  // returns a hash of the exception stack trace for deduplication purposes
  jlong computeDedupToken(jthrowable exception) const;
};

} /* namespace jazzer */
