# Copyright 2021 Code Intelligence GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM ubuntu:20.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y curl git python3 python-is-python3 openjdk-11-jdk-headless

WORKDIR /root
RUN curl -L https://github.com/bazelbuild/bazelisk/releases/download/v1.11.0/bazelisk-linux-amd64 -o /usr/bin/bazelisk && \
    chmod +x /usr/bin/bazelisk && \
    git clone --depth=1 https://github.com/CodeIntelligenceTesting/jazzer.git && \
    cd jazzer && \
    # The LLVM toolchain requires ld and ld.gold to exist, but does not use them.
    touch /usr/bin/ld && \
    touch /usr/bin/ld.gold && \
    BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN=1 \
    bazelisk build --config=toolchain --extra_toolchains=@llvm_toolchain//:cc-toolchain-x86_64-linux \
      //agent:jazzer_agent_deploy //driver:jazzer_driver

# :debug includes a busybox shell, which is needed for libFuzzer's use of system() for e.g. the
# -fork and -minimize_crash commands.
FROM gcr.io/distroless/java:debug

COPY --from=builder /root/jazzer/bazel-bin/agent/jazzer_agent_deploy.jar /root/jazzer/bazel-bin/driver/jazzer_driver /app/
# system() expects the shell at /bin/sh, but the image has it at /busybox/sh. We create a symlink,
# but have to use the long form as a simple RUN <command> also requires /bin/sh.
RUN ["/busybox/sh", "-c", "ln -s /busybox/sh /bin/sh"]
WORKDIR /fuzzing
ENTRYPOINT [ "/app/jazzer_driver" ]
