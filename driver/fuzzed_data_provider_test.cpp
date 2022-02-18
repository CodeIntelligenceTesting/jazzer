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

#include "fuzzed_data_provider.h"

#include <cstddef>
#include <cstdint>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "fuzz_target_runner.h"
#include "gflags/gflags.h"
#include "gtest/gtest.h"
#include "jvm_tooling.h"
#include "tools/cpp/runfiles/runfiles.h"

DECLARE_string(cp);
DECLARE_string(jvm_args);
DECLARE_bool(hooks);

DECLARE_string(target_class);
DECLARE_string(target_args);

namespace jazzer {

std::pair<std::string, std::size_t> FixUpModifiedUtf8(const uint8_t* pos,
                                                      std::size_t max_bytes,
                                                      jint max_length,
                                                      bool ascii_only,
                                                      bool stop_on_backslash);

std::pair<std::string, std::size_t> FixUpRemainingModifiedUtf8(
    const std::string& str, bool ascii_only, bool stop_on_backslash) {
  return FixUpModifiedUtf8(reinterpret_cast<const uint8_t*>(str.c_str()),
                           str.length(), std::numeric_limits<jint>::max(),
                           ascii_only, stop_on_backslash);
}

// Work around the fact that size_t is unsigned long on Linux and unsigned long
// long on Windows.
std::size_t operator"" _z(unsigned long long x) { return x; }

using namespace std::literals::string_literals;
TEST(FixUpModifiedUtf8Test, FullUtf8_ContinueOnBackslash) {
  EXPECT_EQ(std::make_pair("jazzer"s, 6_z),
            FixUpRemainingModifiedUtf8("jazzer"s, false, false));
  EXPECT_EQ(std::make_pair("ja\xC0\x80zzer"s, 7_z),
            FixUpRemainingModifiedUtf8("ja\0zzer"s, false, false));
  EXPECT_EQ(std::make_pair("ja\xC0\x80\xC0\x80zzer"s, 8_z),
            FixUpRemainingModifiedUtf8("ja\0\0zzer"s, false, false));
  EXPECT_EQ(std::make_pair("ja\\zzer"s, 7_z),
            FixUpRemainingModifiedUtf8("ja\\zzer"s, false, false));
  EXPECT_EQ(std::make_pair("ja\\\\zzer"s, 8_z),
            FixUpRemainingModifiedUtf8("ja\\\\zzer"s, false, false));
  EXPECT_EQ(std::make_pair("€ß"s, 5_z),
            FixUpRemainingModifiedUtf8(u8"€ß"s, false, false));
}

TEST(FixUpModifiedUtf8Test, AsciiOnly_ContinueOnBackslash) {
  EXPECT_EQ(std::make_pair("jazzer"s, 6_z),
            FixUpRemainingModifiedUtf8("jazzer"s, true, false));
  EXPECT_EQ(std::make_pair("ja\xC0\x80zzer"s, 7_z),
            FixUpRemainingModifiedUtf8("ja\0zzer"s, true, false));
  EXPECT_EQ(std::make_pair("ja\xC0\x80\xC0\x80zzer"s, 8_z),
            FixUpRemainingModifiedUtf8("ja\0\0zzer"s, true, false));
  EXPECT_EQ(std::make_pair("ja\\zzer"s, 7_z),
            FixUpRemainingModifiedUtf8("ja\\zzer"s, true, false));
  EXPECT_EQ(std::make_pair("ja\\\\zzer"s, 8_z),
            FixUpRemainingModifiedUtf8("ja\\\\zzer"s, true, false));
  EXPECT_EQ(std::make_pair("\x62\x02\x2C\x43\x1F"s, 5_z),
            FixUpRemainingModifiedUtf8(u8"€ß"s, true, false));
}

TEST(FixUpModifiedUtf8Test, FullUtf8_StopOnBackslash) {
  EXPECT_EQ(std::make_pair("jazzer"s, 6_z),
            FixUpRemainingModifiedUtf8("jazzer"s, false, true));
  EXPECT_EQ(std::make_pair("ja\xC0\x80zzer"s, 7_z),
            FixUpRemainingModifiedUtf8("ja\0zzer"s, false, true));
  EXPECT_EQ(std::make_pair("ja\xC0\x80\xC0\x80zzer"s, 8_z),
            FixUpRemainingModifiedUtf8("ja\0\0zzer"s, false, true));
  EXPECT_EQ(std::make_pair("ja"s, 4_z),
            FixUpRemainingModifiedUtf8("ja\\zzer"s, false, true));
  EXPECT_EQ(std::make_pair("ja\\zzer"s, 8_z),
            FixUpRemainingModifiedUtf8("ja\\\\zzer"s, false, true));
}

TEST(FixUpModifiedUtf8Test, AsciiOnly_StopOnBackslash) {
  EXPECT_EQ(std::make_pair("jazzer"s, 6_z),
            FixUpRemainingModifiedUtf8("jazzer"s, true, true));
  EXPECT_EQ(std::make_pair("ja\xC0\x80zzer"s, 7_z),
            FixUpRemainingModifiedUtf8("ja\0zzer"s, true, true));
  EXPECT_EQ(std::make_pair("ja\xC0\x80\xC0\x80zzer"s, 8_z),
            FixUpRemainingModifiedUtf8("ja\0\0zzer"s, true, true));
  EXPECT_EQ(std::make_pair("ja"s, 4_z),
            FixUpRemainingModifiedUtf8("ja\\zzer"s, true, true));
  EXPECT_EQ(std::make_pair("ja\\zzer"s, 8_z),
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

    jvm_ = std::make_unique<JVM>("test_executable", "1234");
  }

  static void TearDownTestCase() { jvm_.reset(nullptr); }

  static std::unique_ptr<JVM> jvm_;
};

std::unique_ptr<JVM> FuzzedDataProviderTest::jvm_ = nullptr;

// see testdata/test/FuzzTargetWithDataProvider.java for the implementation
// of the fuzz target that asserts that the correct values are received from
// the data provider.
const uint8_t kInput[] = {
    // Bytes read from the start
    0x01, 0x02,  // consumeBytes(2): {0x01, 0x02}

    'j', 'a', 'z', 'z', 'e', 'r',   // consumeString(6): "jazzer"
    'j', 'a', 0x00, 'z', 'e', 'r',  // consumeString(6): "ja\u0000zer"
    0xE2, 0x82, 0xAC, 0xC3, 0x9F,   // consumeString(2): "€ẞ"

    'j', 'a', 'z', 'z', 'e', 'r',   // consumeAsciiString(6): "jazzer"
    'j', 'a', 0x00, 'z', 'e', 'r',  // consumeAsciiString(6): "ja\u0000zer"
    0xE2, 0x82, 0xAC, 0xC3,
    0x9F,  // consumeAsciiString(5): "\u0062\u0002\u002C\u0043\u001F"

    false, false, true, false,
    true,  // consumeBooleans(5): { false, false, true, false, true }
    0xEF, 0xDC, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC,
    0xFE,  // consumeLongs(2): { 0x0123456789ABCDEF, 0xFEDCBA9876543210 }

    0x78, 0x56, 0x34, 0x12,  // consumeInts(3): { 0x12345678 }
    0x56, 0x34, 0x12,        // consumeLong():

    // Bytes read from the end
    0x02, 0x03, 0x02, 0x04,  // 4x pickValue in array with five elements

    0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56,
    0x78,  // consumed but unused by consumeDouble()
    10,    // -max for next consumeDouble
    0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56,
    0x78,  // consumed but unused by consumeDouble()
    9,     // max for next consumeDouble
    0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56,
    0x78,  // consumed but unused by consumeDouble()
    8,     // -min for next consumeDouble
    0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56,
    0x78,  // consumed but unused by consumeDouble()
    7,     // min for next consumeDouble
    0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56,
    0x78,  // consumed but unused by consumeDouble()
    6,     // -denorm_min for next consumeDouble
    0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56,
    0x78,  // consumed but unused by consumeDouble()
    5,     // denorm_min for next consumeDouble
    0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56,
    0x78,  // consumed but unused by consumeDouble()
    4,     // NaN for next consumeDouble
    0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56,
    0x78,  // consumed but unused by consumeDouble()
    3,     // -infinity for next consumeDouble
    0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56,
    0x78,  // consumed but unused by consumeDouble()
    2,     // infinity for next consumeDouble
    0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56,
    0x78,  // consumed but unused by consumeDouble()
    1,     // -0.0 for next consumeDouble
    0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56,
    0x78,  // consumed but unused by consumeDouble()
    0,     // 0.0 for next consumeDouble

    0x12, 0x34, 0x56, 0x78, 0x90,  // consumed but unused by consumeFloat()
    10,                            // -max for next consumeFloat
    0x12, 0x34, 0x56, 0x78, 0x90,  // consumed but unused by consumeFloat()
    9,                             // max for next consumeFloat
    0x12, 0x34, 0x56, 0x78, 0x90,  // consumed but unused by consumeFloat()
    8,                             // -min for next consumeFloat
    0x12, 0x34, 0x56, 0x78, 0x90,  // consumed but unused by consumeFloat()
    7,                             // min for next consumeFloat
    0x12, 0x34, 0x56, 0x78, 0x90,  // consumed but unused by consumeFloat()
    6,                             // -denorm_min for next consumeFloat
    0x12, 0x34, 0x56, 0x78, 0x90,  // consumed but unused by consumeFloat()
    5,                             // denorm_min for next consumeFloat
    0x12, 0x34, 0x56, 0x78, 0x90,  // consumed but unused by consumeFloat()
    4,                             // NaN for next consumeFloat
    0x12, 0x34, 0x56, 0x78, 0x90,  // consumed but unused by consumeFloat()
    3,                             // -infinity for next consumeFloat
    0x12, 0x34, 0x56, 0x78, 0x90,  // consumed but unused by consumeFloat()
    2,                             // infinity for next consumeFloat
    0x12, 0x34, 0x56, 0x78, 0x90,  // consumed but unused by consumeFloat()
    1,                             // -0.0 for next consumeFloat
    0x12, 0x34, 0x56, 0x78, 0x90,  // consumed but unused by consumeFloat()
    0,                             // 0.0 for next consumeFloat

    0x88, 0xAB, 0x61, 0xCB, 0x32, 0xEB, 0x30,
    0xF9,  // consumeDouble(13.37, 31.337): 30.859126145478349 (small range)
    0x51, 0xF6, 0x1F,
    0x3A,  // consumeFloat(123.0, 777.0): 271.49084 (small range)
    0x11, 0x4D, 0xFD, 0x54, 0xD6, 0x3D, 0x43, 0x73,
    0x39,  // consumeRegularDouble(): 8.0940194040236032e+307
    0x16, 0xCF, 0x3D, 0x29, 0x4A,  // consumeRegularFloat(): -2.8546307e+38

    0x61, 0xCB, 0x32, 0xEB, 0x30, 0xF9, 0x51,
    0xF6,                    // consumeProbabilityDouble(): 0.96218831486039413
    0x1F, 0x3A, 0x11, 0x4D,  // consumeProbabilityFloat(): 0.30104411
    0xFD, 0x54, 0xD6, 0x3D, 0x43, 0x73, 0x39,
    0x16,                    // consumeProbabilityDouble(): 0.086814121166605432
    0xCF, 0x3D, 0x29, 0x4A,  // consumeProbabilityFloat(): 0.28969181

    0x01,  // consumeInt(0x12345678, 0x12345679): 0x12345679
    0x78,  // consumeInt(-0x12345678, -0x12345600): -0x12345600
    0x78, 0x56, 0x34, 0x12,  // consumeInt(): 0x12345678

    0x02,  // consumeByte(0x12, 0x22): 0x14
    0x7F,  // consumeByte(): 0x7F

    0x01,  // consumeBool(): true
};

TEST_F(FuzzedDataProviderTest, FuzzTargetWithDataProvider) {
  FLAGS_target_class = "test.FuzzTargetWithDataProvider";
  FLAGS_target_args = "";
  FuzzTargetRunner fuzz_target_runner(*jvm_);

  ASSERT_EQ(RunResult::kOk, fuzz_target_runner.Run(kInput, sizeof(kInput)));
}

constexpr std::size_t kValidModifiedUtf8NumRuns = 10000;
constexpr std::size_t kValidModifiedUtf8NumBytes = 100000;
constexpr uint32_t kValidModifiedUtf8Seed = 0x12345678;

TEST_F(FuzzedDataProviderTest, InvalidModifiedUtf8AfterFixup) {
  auto modified_utf8_validator = jvm_->FindClass("test.ModifiedUtf8Encoder");
  ASSERT_NE(nullptr, modified_utf8_validator);
  auto string_to_modified_utf_bytes = jvm_->GetStaticMethodID(
      modified_utf8_validator, "encode", "(Ljava/lang/String;)[B");
  ASSERT_NE(nullptr, string_to_modified_utf_bytes);
  auto& env = jvm_->GetEnv();
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
