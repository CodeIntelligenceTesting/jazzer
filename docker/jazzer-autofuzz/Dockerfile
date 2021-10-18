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

FROM cifuzz/jazzer as jazzer

FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y curl openjdk-11-jdk-headless

WORKDIR /app
RUN curl -L 'https://github.com/coursier/coursier/releases/download/v2.0.16/coursier.jar' -o coursier.jar && \
    chmod +x coursier.jar

COPY entrypoint.sh /app/
COPY --from=jazzer /app/jazzer_agent_deploy.jar /app/jazzer_driver /app/

WORKDIR /fuzzing
ENTRYPOINT ["/app/entrypoint.sh"]
