/*
 * Copyright 2023 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iostream>

#include "slicer/writer.h"

class JazzerJvmtiAllocator : public dex::Writer::Allocator {
 public:
  JazzerJvmtiAllocator(jvmtiEnv* jvmti_env) : jvmti_env_(jvmti_env) {}

  virtual void* Allocate(size_t size) {
    unsigned char* alloc = nullptr;
    jvmtiError error_num = jvmti_env_->Allocate(size, &alloc);

    if (error_num != JVMTI_ERROR_NONE) {
      std::cerr << "JazzerJvmtiAllocator Allocation error. JVMTI error: "
                << error_num << std::endl;
    }

    return (void*)alloc;
  }

  virtual void Free(void* ptr) {
    if (ptr == nullptr) {
      return;
    }

    jvmtiError error_num = jvmti_env_->Deallocate((unsigned char*)ptr);

    if (error_num != JVMTI_ERROR_NONE) {
      std::cout << "JazzerJvmtiAllocator Free error. JVMTI error: " << error_num
                << std::endl;
    }
  }

 private:
  jvmtiEnv* jvmti_env_;
};
