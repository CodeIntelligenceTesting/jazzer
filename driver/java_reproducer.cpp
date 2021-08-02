// Copyright 2021 Code Intelligence GmbH
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

#include "java_reproducer.h"

#include "fuzzed_data_provider.h"
#include "jvm_tooling.h"

namespace {
const char kRecordingFuzzedDataProviderClass[] =
    "com/code_intelligence/jazzer/runtime/RecordingFuzzedDataProvider";
}

namespace jazzer {
jobject GetFuzzedDataProviderJavaObject(const JVM &jvm) {
  static jobject java_object = nullptr;
  if (java_object == nullptr) {
    jclass java_class = jvm.FindClass(kFuzzedDataProviderImplClass);
    jmethodID java_constructor = jvm.GetMethodID(java_class, "<init>", "()V");
    jobject local_ref = jvm.GetEnv().NewObject(java_class, java_constructor);
    // We leak a global reference here as it will be used until JVM exit.
    java_object = jvm.GetEnv().NewGlobalRef(local_ref);
  }
  return java_object;
}

jobject GetRecordingFuzzedDataProviderJavaObject(const JVM &jvm) {
  auto &env = jvm.GetEnv();
  jclass java_class = jvm.FindClass(kRecordingFuzzedDataProviderClass);
  jmethodID java_make_proxy = jvm.GetStaticMethodID(
      java_class, "makeFuzzedDataProviderProxy",
      "()Lcom/code_intelligence/jazzer/api/FuzzedDataProvider;", true);
  jobject local_ref = env.CallStaticObjectMethod(java_class, java_make_proxy);
  if (env.ExceptionCheck()) {
    env.ExceptionDescribe();
    exit(1);
  }
  // This global reference is deleted in SerializeRecordingFuzzedDataProvider.
  jobject global_ref = env.NewGlobalRef(local_ref);
  env.DeleteLocalRef(local_ref);
  return global_ref;
}

std::string SerializeRecordingFuzzedDataProvider(const JVM &jvm,
                                                 jobject recorder) {
  auto &env = jvm.GetEnv();
  jclass java_class = jvm.FindClass(kRecordingFuzzedDataProviderClass);
  jmethodID java_serialize =
      jvm.GetStaticMethodID(java_class, "serializeFuzzedDataProviderProxy",
                            "(Lcom/code_intelligence/jazzer/api/"
                            "FuzzedDataProvider;)Ljava/lang/String;",
                            true);
  auto serialized_recorder =
      (jstring)env.CallStaticObjectMethod(java_class, java_serialize, recorder);
  env.DeleteLocalRef(java_class);
  env.DeleteGlobalRef(recorder);
  if (env.ExceptionCheck()) {
    env.ExceptionDescribe();
    exit(1);
  }
  const char *serialized_recorder_cstr =
      env.GetStringUTFChars(serialized_recorder, nullptr);
  std::string out(serialized_recorder_cstr);
  env.ReleaseStringUTFChars(serialized_recorder, serialized_recorder_cstr);
  env.DeleteLocalRef(serialized_recorder);
  return out;
}
}  // namespace jazzer
