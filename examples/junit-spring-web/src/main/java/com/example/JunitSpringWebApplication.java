/*
 * Copyright 2024 Code Intelligence GmbH
 *
 * By downloading, you agree to the Code Intelligence Jazzer Terms and Conditions.
 *
 * The Code Intelligence Jazzer Terms and Conditions are provided in LICENSE-JAZZER.txt
 * located in the root directory of the project.
 */

package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class JunitSpringWebApplication {
  public static final class HelloRequest {
    public static final HelloRequest DEFAULT = new HelloRequest();

    String prefix = "Hello ";
    String name = "World";
    String suffix = "!";

    public String getPrefix() {
      return prefix;
    }

    public void setPrefix(String prefix) {
      this.prefix = prefix;
    }

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public String getSuffix() {
      return suffix;
    }

    public void setSuffix(String suffix) {
      this.suffix = suffix;
    }
  }

  @GetMapping("/hello")
  public String sayHello(@RequestParam(required = false, defaultValue = "World") String name) {
    return "Hello " + name;
  }

  @GetMapping("/buggy-hello")
  public String buggyHello(@RequestParam(required = false, defaultValue = "World") String name)
      throws Error {
    if (name.equals("error")) {
      throw new Error("Error found!");
    }
    return "Hello " + name;
  }

  @PostMapping("/hello")
  public String postHello(@RequestBody HelloRequest request) {
    if ("error".equals(request.name)) {
      throw new Error("Error found!");
    }
    return request.prefix + request.name + request.suffix;
  }

  public static void main(String[] args) {
    SpringApplication.run(JunitSpringWebApplication.class, args);
  }
}
