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
    ./bazelisk-linux-amd64 build --config=toolchain //agent:jazzer_agent_deploy.jar //driver:jazzer_driver

FROM gcr.io/distroless/java

COPY --from=builder /root/jazzer/bazel-bin/agent/jazzer_agent_deploy.jar /root/jazzer/bazel-bin/driver/jazzer_driver /app/
ENV LD_LIBRARY_PATH=${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}/usr/lib/jvm/java-11-openjdk-amd64/lib/server
WORKDIR /fuzzing
ENTRYPOINT [ "/app/jazzer_driver", "-artifact_prefix=/fuzzing/", "--reproducer_path=/fuzzing" ]
