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

#include "jvm_tooling.h"

#include "coverage_tracker.h"
#include "fuzz_target_runner.h"
#include "gflags/gflags.h"
#include "gtest/gtest.h"
#include "tools/cpp/runfiles/runfiles.h"

DECLARE_string(cp);
DECLARE_string(jvm_args);
DECLARE_string(target_class);
DECLARE_string(target_args);
DECLARE_string(agent_path);
DECLARE_string(instrumentation_excludes);

#ifdef _WIN32
#define ARG_SEPARATOR ";"
#else
#define ARG_SEPARATOR ":"
#endif

namespace jazzer {

std::vector<std::string> splitOnSpace(const std::string &s);

TEST(SpaceSplit, SpaceSplitSimple) {
  ASSERT_EQ((std::vector<std::string>{"first", "se\\ cond", "third"}),
            splitOnSpace("first se\\ cond      third"));
}

class JvmToolingTest : public ::testing::Test {
 protected:
  // After DestroyJavaVM() no new JVM instance can be created in the same
  // process, so we set up a single JVM instance for this test binary which gets
  // destroyed after all tests in this test suite have finished.
  static void SetUpTestCase() {
    FLAGS_jvm_args =
        "-Denv1=va\\" ARG_SEPARATOR "l1\\\\" ARG_SEPARATOR "-Denv2=val2";
    FLAGS_instrumentation_excludes = "**";
    using ::bazel::tools::cpp::runfiles::Runfiles;
    Runfiles *runfiles = Runfiles::CreateForTest();
    FLAGS_cp = runfiles->Rlocation(FLAGS_cp);

    jvm_ = std::make_unique<JVM>("test_executable", "1234");
  }

  static void TearDownTestCase() { jvm_.reset(nullptr); }

  static std::unique_ptr<JVM> jvm_;
};

std::unique_ptr<JVM> JvmToolingTest::jvm_ = nullptr;

TEST_F(JvmToolingTest, ClassNotFound) {
  ASSERT_THROW(jvm_->FindClass(""), std::runtime_error);
  ASSERT_THROW(jvm_->FindClass("test.NonExistingClass"), std::runtime_error);
  ASSERT_THROW(jvm_->FindClass("test/NonExistingClass"), std::runtime_error);
}

TEST_F(JvmToolingTest, ClassInClassPath) {
  ASSERT_NE(nullptr, jvm_->FindClass("test.PropertyPrinter"));
  ASSERT_NE(nullptr, jvm_->FindClass("test/PropertyPrinter"));
}

TEST_F(JvmToolingTest, JniProperties) {
  auto property_printer_class = jvm_->FindClass("test.PropertyPrinter");
  ASSERT_NE(nullptr, property_printer_class);
  auto method_id =
      jvm_->GetStaticMethodID(property_printer_class, "printProperty",
                              "(Ljava/lang/String;)Ljava/lang/String;");
  ASSERT_NE(nullptr, method_id);

  auto &env = jvm_->GetEnv();
  for (const auto &el : std::vector<std::pair<std::string, std::string>>{
           {"not set property", ""},
           {"env1", "va" ARG_SEPARATOR "l1\\"},
           {"env2", "val2"}}) {
    jstring str = env.NewStringUTF(el.first.c_str());
    auto ret = (jstring)env.CallStaticObjectMethod(property_printer_class,
                                                   method_id, str);
    ASSERT_FALSE(env.ExceptionCheck());
    if (el.second.empty()) {
      ASSERT_EQ(nullptr, ret);
    } else {
      ASSERT_NE(nullptr, ret);
      jboolean is_copy;
      ASSERT_EQ(el.second, jvm_->GetEnv().GetStringUTFChars(ret, &is_copy));
    }
  }
}

TEST_F(JvmToolingTest, SimpleFuzzTarget) {
  // see testdata/test/SimpleFuzzTarget.java for the implementation of the fuzz
  // target
  FLAGS_target_class = "test.SimpleFuzzTarget";
  FLAGS_target_args = "";
  FuzzTargetRunner fuzz_target_runner(*jvm_);

  // normal case: fuzzerTestOneInput returns false
  std::string input("random");
  ASSERT_EQ(RunResult::kOk, fuzz_target_runner.Run(
                                (const uint8_t *)input.c_str(), input.size()));

  // exception is thrown in fuzzerTestOneInput
  input = "crash";
  ASSERT_EQ(
      RunResult::kException,
      fuzz_target_runner.Run((const uint8_t *)input.c_str(), input.size()));
}

class ExceptionPrinterTest : public ExceptionPrinter {
 public:
  ExceptionPrinterTest(JVM &jvm) : ExceptionPrinter(jvm), jvm_(jvm) {}

  std::string TriggerJvmException() {
    jclass illegal_argument_exception =
        jvm_.FindClass("java.lang.IllegalArgumentException");
    jvm_.GetEnv().ThrowNew(illegal_argument_exception, "Test");
    jthrowable exception = jvm_.GetEnv().ExceptionOccurred();
    jvm_.GetEnv().ExceptionClear();
    return getStackTrace(exception);
  }

 private:
  const JVM &jvm_;
};

TEST_F(JvmToolingTest, ExceptionPrinter) {
  ExceptionPrinterTest exception_printer(*jvm_);
  // a.k.a std::string.startsWith(java.lang...)
  ASSERT_TRUE(exception_printer.TriggerJvmException().rfind(
                  "java.lang.IllegalArgumentException", 0) == 0);
}

TEST_F(JvmToolingTest, FuzzTargetWithInit) {
  // see testdata/test/FuzzTargetWithInit.java for the implementation of the
  // fuzz target. All string arguments provided in fuzzerInitialize(String[])
  // will cause a crash if input in fuzzerTestOneInput(byte[]).
  FLAGS_target_class = "test.FuzzTargetWithInit";
  FLAGS_target_args = "crash_now crash_harder";
  FuzzTargetRunner fuzz_target_runner(*jvm_);

  // normal case: fuzzerTestOneInput returns false
  std::string input("random");
  ASSERT_EQ(RunResult::kOk, fuzz_target_runner.Run(
                                (const uint8_t *)input.c_str(), input.size()));

  input = "crash_now";
  ASSERT_EQ(
      RunResult::kException,
      fuzz_target_runner.Run((const uint8_t *)input.c_str(), input.size()));

  input = "this is harmless";
  ASSERT_EQ(RunResult::kOk, fuzz_target_runner.Run(
                                (const uint8_t *)input.c_str(), input.size()));

  input = "crash_harder";
  ASSERT_EQ(
      RunResult::kException,
      fuzz_target_runner.Run((const uint8_t *)input.c_str(), input.size()));
}

TEST_F(JvmToolingTest, TestCoverageMap) {
  auto coverage_counters_array = CoverageTracker::GetCoverageCounters();
  ASSERT_EQ(0, coverage_counters_array[0]);

  FLAGS_target_class = "test.FuzzTargetWithCoverage";
  FLAGS_target_args = "";
  FuzzTargetRunner fuzz_target_runner(*jvm_);
  // run a fuzz target input which will cause the first coverage counter to
  // increase
  fuzz_target_runner.Run(nullptr, 0);
  ASSERT_EQ(1, coverage_counters_array[0]);

  // calling the fuzz target twice more
  fuzz_target_runner.Run(nullptr, 0);
  fuzz_target_runner.Run(nullptr, 0);
  ASSERT_EQ(3, coverage_counters_array[0]);
}
}  // namespace jazzer
