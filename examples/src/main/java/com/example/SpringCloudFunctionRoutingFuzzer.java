/*
 * Copyright 2025 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.LogManager;
import org.springframework.cloud.function.context.FunctionProperties;
import org.springframework.cloud.function.context.catalog.SimpleFunctionRegistry;
import org.springframework.cloud.function.context.config.RoutingFunction;
import org.springframework.cloud.function.json.JacksonMapper;
import org.springframework.messaging.Message;
import org.springframework.messaging.converter.CompositeMessageConverter;
import org.springframework.messaging.converter.StringMessageConverter;
import org.springframework.messaging.support.MessageBuilder;

/**
 * Reproduce <a href="https://spring.io/security/cve-2022-22963">CVE-2022-22963</a> by fuzzing the
 * routing-expression header in Spring Cloud Function.
 */
public class SpringCloudFunctionRoutingFuzzer {
  private static RoutingFunction router;

  public static void fuzzerInitialize() {
    LogManager.getLogManager().getLogger("").setLevel(Level.SEVERE);
    // Empty function registry
    SimpleFunctionRegistry registry =
        new SimpleFunctionRegistry(
            null,
            new CompositeMessageConverter(Arrays.asList(new StringMessageConverter())),
            new JacksonMapper(new ObjectMapper()));
    router = new RoutingFunction(registry, new FunctionProperties());
  }

  public static void fuzzerTestOneInput(String payload, String expr) {
    try {
      Message<String> message =
          MessageBuilder.withPayload(payload)
              .setHeader("spring.cloud.function.routing-expression", expr)
              .build();
      router.apply(message);
    } catch (Throwable ignored) {
      // Most inputs will cause parsing or routing errors; that is fine.
    }
  }
}
