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

#include <cstddef>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "gflags/gflags.h"
#include "gtest/gtest.h"
#include "jvm_tooling.h"
#include "tools/cpp/runfiles/runfiles.h"

DECLARE_string(cp);
DECLARE_bool(hooks);

namespace jazzer {

std::pair<std::string, jint> FixUpModifiedUtf8(const uint8_t* pos,
                                               jint max_bytes, jint max_length,
                                               bool ascii_only,
                                               bool stop_on_backslash);

std::pair<std::string, jint> FixUpRemainingModifiedUtf8(
    const std::string& str, bool ascii_only, bool stop_on_backslash) {
  return FixUpModifiedUtf8(reinterpret_cast<const uint8_t*>(str.c_str()),
                           str.length(), std::numeric_limits<jint>::max(),
                           ascii_only, stop_on_backslash);
}

std::pair<std::string, jint> expect(const std::string& s, jint i) {
  return std::make_pair(s, i);
}

using namespace std::literals::string_literals;
TEST(FixUpModifiedUtf8Test, FullUtf8_ContinueOnBackslash) {
  EXPECT_EQ(expect("jazzer"s, 6),
            FixUpRemainingModifiedUtf8("jazzer"s, false, false));
  EXPECT_EQ(expect("ja\xC0\x80zzer"s, 7),
            FixUpRemainingModifiedUtf8("ja\0zzer"s, false, false));
  EXPECT_EQ(expect("ja\xC0\x80\xC0\x80zzer"s, 8),
            FixUpRemainingModifiedUtf8("ja\0\0zzer"s, false, false));
  EXPECT_EQ(expect("ja\\zzer"s, 7),
            FixUpRemainingModifiedUtf8("ja\\zzer"s, false, false));
  EXPECT_EQ(expect("ja\\\\zzer"s, 8),
            FixUpRemainingModifiedUtf8("ja\\\\zzer"s, false, false));
  EXPECT_EQ(expect("€ß"s, 5),
            FixUpRemainingModifiedUtf8(u8"€ß"s, false, false));
}

TEST(FixUpModifiedUtf8Test, AsciiOnly_ContinueOnBackslash) {
  EXPECT_EQ(expect("jazzer"s, 6),
            FixUpRemainingModifiedUtf8("jazzer"s, true, false));
  EXPECT_EQ(expect("ja\xC0\x80zzer"s, 7),
            FixUpRemainingModifiedUtf8("ja\0zzer"s, true, false));
  EXPECT_EQ(expect("ja\xC0\x80\xC0\x80zzer"s, 8),
            FixUpRemainingModifiedUtf8("ja\0\0zzer"s, true, false));
  EXPECT_EQ(expect("ja\\zzer"s, 7),
            FixUpRemainingModifiedUtf8("ja\\zzer"s, true, false));
  EXPECT_EQ(expect("ja\\\\zzer"s, 8),
            FixUpRemainingModifiedUtf8("ja\\\\zzer"s, true, false));
  EXPECT_EQ(expect("\x62\x02\x2C\x43\x1F"s, 5),
            FixUpRemainingModifiedUtf8(u8"€ß"s, true, false));
}

TEST(FixUpModifiedUtf8Test, FullUtf8_StopOnBackslash) {
  EXPECT_EQ(expect("jazzer"s, 6),
            FixUpRemainingModifiedUtf8("jazzer"s, false, true));
  EXPECT_EQ(expect("ja\xC0\x80zzer"s, 7),
            FixUpRemainingModifiedUtf8("ja\0zzer"s, false, true));
  EXPECT_EQ(expect("ja\xC0\x80\xC0\x80zzer"s, 8),
            FixUpRemainingModifiedUtf8("ja\0\0zzer"s, false, true));
  EXPECT_EQ(expect("ja"s, 4),
            FixUpRemainingModifiedUtf8("ja\\zzer"s, false, true));
  EXPECT_EQ(expect("ja\\zzer"s, 8),
            FixUpRemainingModifiedUtf8("ja\\\\zzer"s, false, true));
}

TEST(FixUpModifiedUtf8Test, AsciiOnly_StopOnBackslash) {
  EXPECT_EQ(expect("jazzer"s, 6),
            FixUpRemainingModifiedUtf8("jazzer"s, true, true));
  EXPECT_EQ(expect("ja\xC0\x80zzer"s, 7),
            FixUpRemainingModifiedUtf8("ja\0zzer"s, true, true));
  EXPECT_EQ(expect("ja\xC0\x80\xC0\x80zzer"s, 8),
            FixUpRemainingModifiedUtf8("ja\0\0zzer"s, true, true));
  EXPECT_EQ(expect("ja"s, 4),
            FixUpRemainingModifiedUtf8("ja\\zzer"s, true, true));
  EXPECT_EQ(expect("ja\\zzer"s, 8),
            FixUpRemainingModifiedUtf8("ja\\\\zzer"s, true, true));
}

class FuzzedDataProviderTest : public ::testing::Test {
 protected:
  // After DestroyJavaVM() no new JVM instance can be created in the same
  // process, so we set up a single JVM instance for this test binary which gets
  // destroyed after all tests in this test suite have finished.
  static void SetUpTestCase() {
    FLAGS_hooks = false;
    using ::bazel::tools::cpp::runfiles::Runfiles;
    Runfiles* runfiles = Runfiles::CreateForTest();
    FLAGS_cp = runfiles->Rlocation(FLAGS_cp);

    jvm_ = std::make_unique<JVM>("test_executable");
  }

  static void TearDownTestCase() { jvm_.reset(nullptr); }

  static std::unique_ptr<JVM> jvm_;
};

std::unique_ptr<JVM> FuzzedDataProviderTest::jvm_ = nullptr;

constexpr std::size_t kValidModifiedUtf8NumRuns = 10000;
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
