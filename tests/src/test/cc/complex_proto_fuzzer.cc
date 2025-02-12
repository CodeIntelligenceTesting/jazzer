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

#include "src/libfuzzer/libfuzzer_macro.h"
#include "src/test/java/com/code_intelligence/jazzer/mutation/mutator/proto/proto2.pb.h"

DEFINE_PROTO_FUZZER(const com::code_intelligence::jazzer::protobuf::TestProtobuf& proto) {
  if (proto.i32() == 1234 && proto.str() == "abcd") {
    abort();
  }
}
