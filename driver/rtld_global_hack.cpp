// Copyright 2022 Code Intelligence GmbH
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

// Upgrades the current shared library to RTLD_GLOBAL so that its exported
// symbols are used to resolve unresolved symbols in shared libraries loaded
// afterwards.
jint JNI_OnLoad(JavaVM *vm, void *reserved) {
  Dl_info info;

  if (!dladdr(reinterpret_cast<const void *>(&JNI_OnLoad), &info) ||
      !info.dli_fname) {
    fprintf(stderr, "Failed to determine our dli_fname\n");
    abort();
  }

  void *handle = dlopen(info.dli_fname, RTLD_NOLOAD | RTLD_GLOBAL | RTLD_NOW);
  if (handle == nullptr) {
    fprintf(stderr, "Failed to upgrade self to RTLD_GLOBAL: %s", dlerror());
    abort();
  }
  dlclose(handle);

  return JNI_VERSION_1_8;
}
