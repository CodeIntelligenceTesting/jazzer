// Copyright 2024 Code Intelligence GmbH
//
// By downloading, you agree to the Code Intelligence Jazzer Terms and
// Conditions.
//
// The Code Intelligence Jazzer Terms and Conditions are provided in
// LICENSE-JAZZER.txt located in the root directory of the project.
//
// This file also contains code licensed under Apache2 license.

#include <cstddef>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "launcher/jvm_tooling.h"
#include "tools/cpp/runfiles/runfiles.h"

namespace jazzer {

std::pair<std::string, jint> FixUpModifiedUtf8(const uint8_t* pos,
                                               jint max_bytes, jint max_length,
                                               bool ascii_only,
                                               bool stop_on_backslash);

class FuzzedDataProviderTest : public ::testing::Test {
 protected:
  // After DestroyJavaVM() no new JVM instance can be created in the same
  // process, so we set up a single JVM instance for this test binary which gets
  // destroyed after all tests in this test suite have finished.
  static void SetUpTestCase() {
    using ::bazel::tools::cpp::runfiles::Runfiles;
    std::unique_ptr<Runfiles> runfiles(Runfiles::CreateForTest());
    FLAGS_cp = runfiles->Rlocation(
        "jazzer/launcher/testdata/fuzz_target_mocks_deploy.jar");

    jvm_ = std::make_unique<JVM>();
  }

  static void TearDownTestCase() { jvm_.reset(nullptr); }

  static std::unique_ptr<JVM> jvm_;
};

std::unique_ptr<JVM> FuzzedDataProviderTest::jvm_ = nullptr;

constexpr std::size_t kValidModifiedUtf8NumRuns = 1000;
constexpr std::size_t kValidModifiedUtf8NumBytes = 100000;
constexpr uint32_t kValidModifiedUtf8Seed = 0x12345678;

TEST_F(FuzzedDataProviderTest, InvalidModifiedUtf8AfterFixup) {
  auto& env = jvm_->GetEnv();
  auto modified_utf8_validator = env.FindClass("test/ModifiedUtf8Encoder");
  ASSERT_NE(nullptr, modified_utf8_validator);
  auto string_to_modified_utf_bytes = env.GetStaticMethodID(
      modified_utf8_validator, "encode", "(Ljava/lang/String;)[B");
  ASSERT_NE(nullptr, string_to_modified_utf_bytes);
  auto random_bytes = std::vector<uint8_t>(kValidModifiedUtf8NumBytes);
  auto random = std::mt19937(kValidModifiedUtf8Seed);
  for (bool ascii_only : {false, true}) {
    for (bool stop_on_backslash : {false, true}) {
      for (std::size_t i = 0; i < kValidModifiedUtf8NumRuns; ++i) {
        std::generate(random_bytes.begin(), random_bytes.end(), random);
        std::string fixed_string;
        std::tie(fixed_string, std::ignore) = FixUpModifiedUtf8(
            random_bytes.data(), random_bytes.size(),
            std::numeric_limits<jint>::max(), ascii_only, stop_on_backslash);

        jstring jni_fixed_string = env.NewStringUTF(fixed_string.c_str());
        auto jni_roundtripped_bytes = (jbyteArray)env.CallStaticObjectMethod(
            modified_utf8_validator, string_to_modified_utf_bytes,
            jni_fixed_string);
        ASSERT_FALSE(env.ExceptionCheck());
        env.DeleteLocalRef(jni_fixed_string);
        jint roundtripped_bytes_length =
            env.GetArrayLength(jni_roundtripped_bytes);
        jbyte* roundtripped_bytes =
            env.GetByteArrayElements(jni_roundtripped_bytes, nullptr);
        auto roundtripped_string =
            std::string(reinterpret_cast<char*>(roundtripped_bytes),
                        roundtripped_bytes_length);
        env.ReleaseByteArrayElements(jni_roundtripped_bytes, roundtripped_bytes,
                                     JNI_ABORT);
        env.DeleteLocalRef(jni_roundtripped_bytes);

        // Verify that the bytes obtained from running our modified UTF-8 fix-up
        // function remain unchanged when turned into a Java string and
        // reencoded into modified UTF-8. This will only happen if the our
        // fix-up function indeed returned valid modified UTF-8.
        ASSERT_EQ(fixed_string, roundtripped_string);
      }
    }
  }
}
}  // namespace jazzer
