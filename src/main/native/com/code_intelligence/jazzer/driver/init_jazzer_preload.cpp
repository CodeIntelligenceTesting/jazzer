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

#include <dlfcn.h>
#include <jni.h>

#include <cstdlib>

#if defined(__ANDROID__)
#define __jni_version__ JNI_VERSION_1_6
#else
#define __jni_version__ JNI_VERSION_1_8
#endif

// The jazzer_preload library, if used, forwards all calls to native libFuzzer
// hooks such as __sanitizer_cov_trace_cmp8 to the Jazzer JNI library. In order
// to load the hook symbols when the library is ready, it needs to be passed a
// handle - the JVM loads libraries with RTLD_LOCAL and thus their symbols
// wouldn't be found as part of the global lookup procedure.
jint JNI_OnLoad(JavaVM *, void *) {
  Dl_info info;

  if (!dladdr(reinterpret_cast<const void *>(&JNI_OnLoad), &info) ||
      !info.dli_fname) {
    fprintf(stderr, "Failed to determine our dli_fname\n");
    abort();
  }

  void *handle = dlopen(info.dli_fname, RTLD_NOLOAD | RTLD_LAZY);
  if (handle == nullptr) {
    fprintf(stderr, "Failed to dlopen self: %s\n", dlerror());
    abort();
  }

  void *preload_init = dlsym(RTLD_DEFAULT, "jazzer_preload_init");
  // jazzer_preload is only preloaded when Jazzer is started with --native, so
  // not finding this method is an expected error.
  if (preload_init) {
    reinterpret_cast<void (*)(void *)>(preload_init)(handle);
  }

  dlclose(handle);

  return __jni_version__;
}
