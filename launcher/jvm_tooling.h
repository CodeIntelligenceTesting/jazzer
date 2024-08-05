// Copyright 2024 Code Intelligence GmbH
//
// By downloading, you agree to the Code Intelligence Jazzer Terms and
// Conditions.
//
// The Code Intelligence Jazzer Terms and Conditions are provided in
// LICENSE-JAZZER.txt located in the root directory of the project.

#pragma once

#include <jni.h>

#include <string>

extern std::string FLAGS_cp;
extern std::string FLAGS_jvm_args;
extern std::string FLAGS_additional_jvm_args;
extern std::string FLAGS_agent_path;

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
  explicit JVM();

  // Destroy the running JVM instance.
  ~JVM();

  // Get the JNI environment for interaction with the running JVM instance.
  JNIEnv &GetEnv() const;
};
} /* namespace jazzer */
