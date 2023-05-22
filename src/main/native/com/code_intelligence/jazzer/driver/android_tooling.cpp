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

#include <cstdlib>
#include <cstring>

#include <jni.h>
#include <dlfcn.h>
#include <iostream>

#include "com_code_intelligence_jazzer_android_AndroidRuntime.h"

const char *RUNTIME_LIBRARY = "libandroid_runtime.so";
const char *EMBEDDED_DIR = "/data/fuzz:/system/lib64";
const char *USE_EMBEDDED = "use_embedded";

std::string getNativeString(JNIEnv* env, jbyteArray javaString) {
  jsize num_bytes = env->GetArrayLength(javaString);
  jbyte* elements = env->GetByteArrayElements(javaString, NULL);

  if (!elements) {
    std::cerr
        << "ERROR: Passed a invalid runtime_libs string."
        << std::endl;
    exit(1);
  }
  std::string nativeString(reinterpret_cast<char*>(elements), num_bytes);

  // Release the element array provided by JNI
  env->ReleaseByteArrayElements(javaString, elements, JNI_ABORT); 

  return nativeString;
}

// Register native methods from the Android Runtime (ART) framework.
[[maybe_unused]] jint
Java_com_code_1intelligence_jazzer_android_AndroidRuntime_registerNatives(
    JNIEnv* env, jclass clazz, jbyteArray runtimeLibs) {
  if (runtimeLibs == nullptr) {
    exit(1); 
  }

  std::string nativeString = getNativeString(env, runtimeLibs);

  if (strcmp(USE_EMBEDDED, nativeString.c_str()) == 0) {
    setenv("LD_LIBRARY_PATH", EMBEDDED_DIR, true);
  }
       
  void *handle = nullptr;
  handle = dlopen(RUNTIME_LIBRARY, RTLD_LAZY);

  if (handle == nullptr) {
    std::cerr
        << "ERROR: Unable to locate runtime libs. Check LD_LIBRARY_PATH."
        << std::endl;
    exit(1);
  }
  // reset errors
  dlerror();

  // Load the symbol from library
  typedef jint (*Register_Frameworks_t)(JNIEnv *);
  Register_Frameworks_t Register_Frameworks;

  Register_Frameworks = reinterpret_cast<Register_Frameworks_t>(
    dlsym(handle, "registerFrameworkNatives"));
  const char* dlsym_error = dlerror();
  if (dlsym_error) {
    exit(1);
  }

  if (Register_Frameworks == nullptr) {
    exit(1);
  }
  return Register_Frameworks(env);
}