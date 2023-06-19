# Selffuzz

This package holds fuzz tests for Jazzer. In order to get around the
constraint that Jazzer cannot instrument its own code, this is a separate
package that takes the built Jazzer jar and shades it such that we can
have the normal Jazzer classes running the fuzzing while our test code
calls the shaded Jazzer classes which have been instrumented.

## Running the tests

```shell
bazel build //selffuzz:jazzer_selffuzz
cifuzz run "<test case name>"
```

## Maven and Bazel

This package contains both Maven and Bazel files. There is no interaction
between them, Bazel is used to integrate with the build system of the wider
project and intellij and Maven is used by `cifuzz` for running the fuzz tests.
Any dependencies used in the tests will need to be specified in both
Maven and Bazel.
