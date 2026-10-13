# Autofuzz mode

The Autofuzz mode enables fuzzing arbitrary methods without having to manually create fuzz targets.
Instead, Jazzer will attempt to generate suitable and varied inputs to a specified methods using only public API functions available on the classpath.

To use Autofuzz, specify the `--autofuzz` flag and provide a fully [qualified method reference](https://docs.oracle.com/javase/specs/jls/se8/html/jls-15.html#jls-15.13), e.g.:
```
--autofuzz=org.apache.commons.imaging.Imaging::getBufferedImage
```
To autofuzz a constructor the `ClassType::new` format can be used.
If there are multiple overloads, and you want Jazzer to only fuzz one, you can optionally specify the signature of the method to fuzz:
```
--autofuzz=org.apache.commons.imaging.Imaging::getBufferedImage(java.io.InputStream,java.util.Map)
```
The format of the signature agrees with that obtained from the part after the `#` of the link to the Javadocs for the particular method.

Under the hood, Jazzer tries various ways of creating objects from the fuzzer input.
For example, if a parameter is an interface or an abstract class, it will look for all concrete implementing classes on the classpath.
Jazzer can also create objects from classes that follow the [builder design pattern](https://www.baeldung.com/creational-design-patterns#builder) or have a default constructor and use setters to set the fields.

Some constructors have undesired side effects or can take a very long time for fuzzed inputs.
Exact constructor references can be excluded via `--autofuzz_constructor_excludes` as a semicolon-separated list:
```
--autofuzz_constructor_excludes='com.example.Dangerous::new(int,java.util.Random);com.example.Dangerous::new(byte[])'
```
The constructor descriptor is exact and uses the same parameter type format as `--autofuzz` method descriptors.
Each exclude must name an accessible constructor that exists when Autofuzz initializes.
Nested classes must be specified with their binary names, for example `com.example.Outer$Inner::new()`.
Globs, regular expressions, and broad `Class::new` excludes are not supported.
Explicitly targeted constructors, for example via `--autofuzz=com.example.Dangerous::new(int)`, are not affected by this option.

Creating objects from fuzzer input can lead to many reported exceptions.
Jazzer addresses this issue by ignoring exceptions that the target method declares to throw.
In addition to that, you can provide a list of exceptions to be ignored during fuzzing via the `--autofuzz_ignore` flag in the form of a comma-separated list.
You can specify concrete exceptions (e.g., `java.lang.NullPointerException`), in which case also subclasses of these exception classes will be ignored, or glob patterns to ignore all exceptions in a specific package (e.g. `java.lang.*` or `com.company.**`).
