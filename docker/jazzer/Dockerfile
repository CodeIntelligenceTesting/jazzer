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
RUN apt-get update && apt-get install -y git python3 python-is-python3 openjdk-11-jdk-headless

WORKDIR /root
RUN git clone --depth=1 https://github.com/CodeIntelligenceTesting/jazzer.git && \
    cd jazzer && \
    # The LLVM toolchain requires ld and ld.gold to exist, but does not use them.
    touch /usr/bin/ld && \
    touch /usr/bin/ld.gold && \
    BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN=1 \
    ./bazelisk-linux-amd64 build --config=toolchain --extra_toolchains=@llvm_toolchain//:cc-toolchain-x86_64-linux \
      //agent:jazzer_agent_deploy.jar //driver:jazzer_driver

FROM gcr.io/distroless/java

COPY --from=builder /root/jazzer/bazel-bin/agent/jazzer_agent_deploy.jar /root/jazzer/bazel-bin/driver/jazzer_driver /app/
WORKDIR /fuzzing
ENTRYPOINT [ "/app/jazzer_driver", "-artifact_prefix=/fuzzing/", "--reproducer_path=/fuzzing" ]
