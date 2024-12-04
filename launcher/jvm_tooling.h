// Copyright 2024 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
