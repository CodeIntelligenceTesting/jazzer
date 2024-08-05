// Copyright 2024 Code Intelligence GmbH
//
// By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
//
// The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
// located in the root directory of the project.

#include "src/libfuzzer/libfuzzer_macro.h"
#include "src/test/java/com/code_intelligence/jazzer/mutation/mutator/proto/proto2.pb.h"

DEFINE_PROTO_FUZZER(const com::code_intelligence::jazzer::protobuf::TestProtobuf& proto) {
  if (proto.i32() == 1234 && proto.str() == "abcd") {
    abort();
  }
}
