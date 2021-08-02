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

#include "com_code_intelligence_jazzer_replay_Replayer.h"

#include <jni.h>

#include "driver/fuzzed_data_provider.h"

namespace {
uint8_t *data = nullptr;
}

void Java_com_code_1intelligence_jazzer_replay_Replayer_feedFuzzedDataProvider(
    JNIEnv *env, jclass, jbyteArray input) {
  if (data == nullptr) {
    jazzer::SetUpFuzzedDataProvider(*env);
  } else {
    delete[] data;
  }

  std::size_t size = env->GetArrayLength(input);
  if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    env->FatalError("Failed to get length of input");
  }
  data = static_cast<uint8_t *>(operator new(size));
  if (data == nullptr) {
    env->FatalError("Failed to allocate memory for a copy of the input");
  }
  env->GetByteArrayRegion(input, 0, size, reinterpret_cast<jbyte *>(data));
  if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    env->FatalError("Failed to copy input");
  }
  jazzer::FeedFuzzedDataProvider(data, size);
}
