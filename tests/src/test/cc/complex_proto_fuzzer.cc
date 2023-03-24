#include "src/libfuzzer/libfuzzer_macro.h"
#include "src/test/java/com/code_intelligence/jazzer/mutation/mutator/proto/proto2.pb.h"

DEFINE_PROTO_FUZZER(const com::code_intelligence::jazzer::protobuf::TestProtobuf& proto) {
  if (proto.i32() == 1234 && proto.str() == "abcd") {
    abort();
  }
}