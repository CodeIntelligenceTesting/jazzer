## Advanced options

* [Using Jazzer Standalone](#using-jazzer-standalone)
* [Passing JVM Arguments](#passing-jvm-arguments)
* [Coverage Instrumentation](#coverage-instrumentation)
* [Trace Instrumentation](#trace-instrumentation)
* [Value Profile](#value-profile)
* [Custom Hooks](#custom-hooks)
* [Keep Going](#keep-going)
* [Export Coverage Information](#export-coverage-information)
* [Native Libraries](#native-libraries)

**Note**: These settings apply to the old fuzzing approach using a `fuzzerTestOneInput` method and the native Jazzer binary. They don't work in the new JUnit integration.

## Using Jazzer Standalone
There are two ways to use Jazzer standalone: by using the `jazzer` binary or by calling the Jazzer main class directly.

### Using the `jazzer` binary
Jazzer is available as a standalone libFuzzer-compiled binary. To call `jazzer` you need to pass it the project
classpath and target class that contains the Fuzz Test.

```shell
jazzer --cp=<classpath> --target_class=<fuzz test class>
```

### Calling the Jazzer main class directly
To call Jazzer directly you need to pass it the project classpath, the path to the `jazzer.jar` and `jazzer-junit.jar`
along with the Jazzer main class `com.code_intelligence.jazzer.Jazzer` and target class that contains the Fuzz Test.

```shell
java -cp <classpath>;<path/to/jazzer.jar>;<path/to/jazzer-junit.jar> com.code_intelligence.jazzer.Jazzer --target_class=<fuzz-test-class> [args...]
```

Optionally you can add other Jazzer arguments with double dash command-line flags.
Because Jazzer is based on libFuzzer, all available libFuzzer arguments can be added with single dash command-line flags.
Please refer to [libFuzzer](https://llvm.org/docs/LibFuzzer.html) for documentation.

Various command line options are available to control the instrumentation and fuzzer execution.
A full list of command-line flags can be printed with the `--help` flag.

### Passing JVM Arguments

When Jazzer is started using the `jazzer` binary, it starts a JVM in which it executes the fuzz target.
Arguments for this JVM can be provided via the `JAVA_OPTS` environment variable.

Alternatively, arguments can also be supplied via the `--jvm_args` argument.
Multiple arguments are delimited by the classpath separator, which is `;` on Windows and `:` else.
For example, to enable preview features as well as set a maximum heap size, add the following to the Jazzer invocation:

```bash
# Windows
--jvm_args=--enable-preview;-Xmx1000m
# Linux & macOS
--jvm_args=--enable-preview:-Xmx1000m
```

Arguments specified with `--jvm_args` take precedence over those in `JAVA_OPTS`.

## Coverage Instrumentation

The Jazzer agent inserts coverage markers into the JVM bytecode during class loading.
It is possible to restrict instrumentation to only a subset of classes with the `--instrumentation_includes` flag.
This is especially useful if coverage inside specific packages is of higher interest,
e.g., the user library under test rather than an external parsing library in which the fuzzer is likely to get lost.
Similarly, there is `--instrumentation_excludes` to exclude specific classes from instrumentation.
Both flags take a list of glob patterns for the java class name separated by colon:

```bash
--instrumentation_includes=com.my_com.**:com.other_com.** --instrumentation_excludes=com.my_com.crypto.**
```

By default, JVM-internal classes and Java as well as Kotlin standard library classes are not instrumented,
so these do not need to be excluded manually.

### Trace Instrumentation

The agent adds additional hooks for tracing compares, integer divisions, switch statements and array indices.
These hooks correspond to [clang's data flow hooks](https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-data-flow).
The particular instrumentation types to apply can be specified using the `--trace` flag, which accepts the following values:

* `cov`: AFL-style edge coverage
* `cmp`: compares (int, long, String) and switch cases
* `div`: divisors in integer divisions
* `gep`: constant array indexes
* `indir`: call through `Method#invoke`
* `all`: shorthand to apply all available instrumentations (except `gep`)

Multiple instrumentation types can be combined with a colon (Linux, macOS) or a semicolon (Windows).

### Value Profile

The run-time flag `-use_value_profile=1` enables [libFuzzer's value profiling mode](https://llvm.org/docs/LibFuzzer.html#value-profile).
When running with this flag, the feedback about compares and constants received from Jazzer's trace instrumentation is associated with the particular bytecode location and used to provide additional coverage instrumentation.
See [ExampleValueProfileFuzzer.java](../examples/src/main/java/com/example/ExampleValueProfileFuzzer.java) for a fuzz target that would be very hard to fuzz without value profile.

### Custom hooks

In order to obtain information about data passed into functions such as `String.equals` or `String.startsWith`, Jazzer hooks invocations to these methods.
This functionality is also available to fuzz targets, where it can be used to implement custom sanitizers or stub out methods that block the fuzzer from progressing (e.g. checksum verifications or random number generation).
See [ExampleFuzzerHooks.java](../examples/src/main/java/com/example/ExampleFuzzerHooks.java) for an example of such a hook.
An example for a sanitizer can be found in [ExamplePathTraversalFuzzerHooks.java](../examples/src/main/java/com/example/ExamplePathTraversalFuzzerHooks.java).

Method hooks can be declared using the `@MethodHook` annotation defined in the `com.code_intelligence.jazzer.api` package, which is contained in `jazzer_standalone.jar` (binary release) or in the Maven artifact [`com.code-intelligence:jazzer-api`](https://search.maven.org/search?q=g:com.code-intelligence%20a:jazzer-api).
See the [javadocs of the `@MethodHook` API](https://codeintelligencetesting.github.io/jazzer-docs/jazzer-api/com/code_intelligence/jazzer/api/MethodHook.html) for more details.

To use the compiled method hooks, they have to be available on the classpath provided by `--cp` and can then be loaded by providing the flag `--custom_hooks`, which takes a colon-separated list of names of classes to load hooks from.
Hooks have to be loaded from separate JAR files so that Jazzer can [add it to the bootstrap class loader search](https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/Instrumentation.html#appendToBootstrapClassLoaderSearch-java.util.jar.JarFile-).
The list of custom hooks can alternatively be specified via the `Jazzer-Hook-Classes` attribute in the fuzz target JAR's manifest.

### Keep Going

With the flag `--keep_going=N` Jazzer continues fuzzing until `N` unique stack traces have been encountered.
Specifically `--keep-going=0` will keep the fuzzer running until another stop condition (e.g. maximum runtime) is met.

Particular stack traces can also be ignored based on their `DEDUP_TOKEN` by passing a comma-separated list of tokens via
`--ignore=<token_1>,<token2>`.

### Export Coverage Information

**Note**: This feature is deprecated. The standalone JaCoCo agent should be used to generate coverage reports.

The internally gathered JaCoCo coverage information can be exported in human-readable and JaCoCo execution data format (`.exec`).
These can help identify code areas that have not been covered by the fuzzer and thus may require more comprehensive fuzz targets or a more extensive initial corpus to reach.

The human-readable report contains coverage information, like branch and line coverage, on file level.
It's useful to get a quick overview about the overall coverage. The flag `--coverage_report=<file>` can be used to generate it.

Similar to the JaCoCo `dump` command, the flag `--coverage_dump=<file>` specifies a coverage dump file, often called `jacoco.exec`, that is generated after the fuzzing run. It contains a binary representation of the gathered coverage data in the JaCoCo format.

The JaCoCo `report` command can be used to generate reports based on this coverage dump.
The JaCoCo CLI tools are available on their [GitHub release page](https://github.com/jacoco/jacoco/releases) as `zip` file.
The report tool is located in the `lib` folder and can be used as described in the JaCoCo [CLI documentation](https://www.eclemma.org/jacoco/trunk/doc/cli.html).
For example the following command generates an HTML report in the folder `report` containing all classes available in `classes.jar` and their coverage as captured in the export `coverage.exec`.
Source code to include in the report is searched for in `some/path/to/sources`.
After execution the `index.html` file in the output folder can be opened in a browser.
```shell
java -jar path/to/jacococli.jar report coverage.exec \
  --classfiles classes.jar \
  --sourcefiles some/path/to/sources \
  --html report \
  --name FuzzCoverageReport
```

### Native Libraries

Jazzer supports fuzzing of native libraries loaded by the JVM, for example via `System.load()`.
For the fuzzer to get coverage feedback, these libraries have to be compiled with `-fsanitize=fuzzer-no-link`.

Additional sanitizers such as AddressSanitizer or UndefinedBehaviorSanitizer are often desirable to uncover bugs inside the native libraries.
The required compilation flags for native libraries are as follows:
- *AddressSanitizer*: `-fsanitize=fuzzer-no-link,address`
- *UndefinedBehaviorSanitizer*: `-fsanitize=fuzzer-no-link,undefined` (add `-fno-sanitize-recover=all` to crash on UBSan reports)

Then, start Jazzer with `--asan` and/or `--ubsan` to automatically preload the sanitizer runtimes.
Jazzer defaults to using the runtimes associated with `clang` on the `PATH`.
If you used a different compiler to compile the native libraries, specify it with `CC` to override this default.
If no compiler is available in your runtime environment (e.g. in OSS-Fuzz) but you have a directory that contains the required sanitier libraries, specify its path in `JAZZER_NATIVE_SANITIZERS_DIR`.

**Note:** On macOS, you may see Gatekeeper warnings when using `--asan` and/or `--ubsan` since these flags cause the native sanitizer libraries to be preloaded into the codesigned `java` executable via `DYLD_INSERT_LIBRARIES`.

Sanitizers other than AddressSanitizer and UndefinedBehaviorSanitizer are not yet supported.
Furthermore, due to the nature of the JVM's GC, LeakSanitizer reports too many false positives to be useful and is thus disabled.

The fuzz targets `ExampleFuzzerWithASan` and `ExampleFuzzerWithUBSan` in the [`examples`](../examples/src/main/java/com/example) directory contain minimal working examples for fuzzing with native libraries.
Also see `TurboJpegFuzzer` for a real-world example.
