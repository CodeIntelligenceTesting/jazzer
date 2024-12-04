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

#include "jvm_tooling.h"

#include <memory>

#include "gtest/gtest.h"
#include "tools/cpp/runfiles/runfiles.h"

#ifdef _WIN32
#define ARG_SEPARATOR ";"
#else
#define ARG_SEPARATOR ":"
#endif

namespace jazzer {

class JvmToolingTest : public ::testing::Test {
 protected:
  // After DestroyJavaVM() no new JVM instance can be created in the same
  // process, so we set up a single JVM instance for this test binary which gets
  // destroyed after all tests in this test suite have finished.
  static void SetUpTestCase() {
    FLAGS_jvm_args =
        "-Denv1=va\\" ARG_SEPARATOR "l1\\\\" ARG_SEPARATOR "-Denv2=val2";
    using ::bazel::tools::cpp::runfiles::Runfiles;
    std::unique_ptr<Runfiles> runfiles(Runfiles::CreateForTest());
    FLAGS_cp = runfiles->Rlocation(
        "jazzer/launcher/testdata/fuzz_target_mocks_deploy.jar");

    jvm_ = std::unique_ptr<JVM>(new JVM());
  }

  static void TearDownTestCase() { jvm_.reset(nullptr); }

  static std::unique_ptr<JVM> jvm_;
};

std::unique_ptr<JVM> JvmToolingTest::jvm_ = nullptr;

TEST_F(JvmToolingTest, JniProperties) {
  auto &env = jvm_->GetEnv();
  auto property_printer_class = env.FindClass("test/PropertyPrinter");
  ASSERT_NE(nullptr, property_printer_class);
  auto method_id =
      env.GetStaticMethodID(property_printer_class, "printProperty",
                            "(Ljava/lang/String;)Ljava/lang/String;");
  ASSERT_NE(nullptr, method_id);

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
      ASSERT_EQ(el.second, env.GetStringUTFChars(ret, &is_copy));
    }
  }
}
}  // namespace jazzer
