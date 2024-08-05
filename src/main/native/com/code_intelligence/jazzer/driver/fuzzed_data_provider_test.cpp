// Copyright 2024 Code Intelligence GmbH
//
// By downloading, you agree to the Code Intelligence Jazzer Terms and
// Conditions.
//
// The Code Intelligence Jazzer Terms and Conditions are provided in
// LICENSE-JAZZER.txt located in the root directory of the project.

#include <jni.h>

#include <cstddef>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "gtest/gtest.h"

namespace jazzer {
std::pair<std::string, jint> FixUpModifiedUtf8(const uint8_t *pos,
                                               jint max_bytes, jint max_length,
                                               bool ascii_only,
                                               bool stop_on_backslash);
}

std::pair<std::string, jint> FixUpRemainingModifiedUtf8(
    const std::string &str, bool ascii_only, bool stop_on_backslash) {
  return jazzer::FixUpModifiedUtf8(
      reinterpret_cast<const uint8_t *>(str.c_str()), str.length(),
      std::numeric_limits<jint>::max(), ascii_only, stop_on_backslash);
}

std::pair<std::string, jint> expect(const std::string &s, jint i) {
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
