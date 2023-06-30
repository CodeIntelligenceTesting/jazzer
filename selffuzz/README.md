# Selffuzz

This package holds fuzz tests for Jazzer. In order to get around the
constraint that Jazzer cannot instrument its own code this is a separate
package that takes the built Jazzer jar and shades it such that we can
have the normal Jazzer classes running the fuzzing while our test code
calls the shaded Jazzer classes which have been instrumented.

## Building and running

```shell
bazel build //...
cifuzz run "<test case name>"
```

The shaded classes will be in the `com.code_intelligence.selffuzz.jazzer` package.

## Maven and Bazel

This package contains both Maven and Bazel files. There is no interaction
between them. Bazel is used to integrate with the build system of the wider
project and to integrate with Intellij and Maven is used by `cifuzz` for running the fuzz tests.
Any dependencies used in the tests must therefore be listed in both Maven and Bazel.

### Jazzer dependency in Maven

In addition to testing the current working version of Jazzer, this also uses it to run the fuzzing by
directly referencing the output jars produced by `bazel build //deploy` in `pom.xml`. Because we're
sidestepping Maven's normal dependency handling, it won't automatically resolve Jazzer's transitive dependencies meaning
they must be manually added to selffuzz's `pom.xml` in order for everything to be available.
