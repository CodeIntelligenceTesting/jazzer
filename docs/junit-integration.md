# JUnit Integration Implementation

Jazzer's JUnit integration starts from
the [`FuzzTest`](../src/main/java/com/code_intelligence/jazzer/junit/FuzzTest.java) annotation. As mentioned in the
annotation's javadoc, our integration runs in one of two modes: fuzzing and regression. Fuzzing mode will generate new
inputs to feed into the tests to find new issues and regression mode will run the tests against previous findings, no
fuzzing is done. The main entrypoints for the actual integration code are found in two of the annotations
on `FuzzTest`: `@ArgumentsSource(FuzzTestArgumentsProvider.class)` and `@ExtendsWith(FuzzTestExtensions.class)`.

Because these same files and functions are involved in two mostly separate sets of functionality, this will look at the
flow of the different methods involved in integrating with JUnit in fuzzing mode (when `JAZZER_FUZZ` is set to any
non-empty value) and in regression mode (when `JAZZER_FUZZ` is not set) separately.

# Fuzzing Flow

## `evaluateExecutionCondition`

It appears that, when running an entire class of tests, JUnit will first call this function on all tests marked
with `@FuzzTest` looking for at least one method to return that it should be run. If a test class has multiple fuzz tests, it
will short circuit at the first that says it's enabled. In fuzzing mode, Jazzer will only run a single test so this will
save this first test and later calls to this function will return enabled for only this test.

## `provideArugments`

This will configure the fuzzing agent to set up code instrumentation, instantiate a `FuzzTestExecutor` and put it into
JUnit's `extensionContext`, then create a stream of a single empty argument set. As the comment mentions, this is so
that JUnit will actually execute the test but the argument will not be used.

## `evaluateExecutionCondition`

This will be called again for each fuzz test that might be run i.e. it does not short circuit. As
stated above, `FuzzTestExtensions` will cache the first test to be checked and only allow that to run so all other tests
will return disabled.

## `interceptTestTemplateMethod`

This will call `invocation.skip()` which prevents invoking the test function with the default set of
arguments `provideArguments` created. It will instead extract the `FuzzTestExecutor` instance from
the `extensionContext` and then calls `FuzzTestExecutor#execute` which creates a `FuzzTargetRunner` to run the actual
fuzzing.

Crashes are saved in `resources/<package>/<test file name>Inputs/<test method name>` and results that are interesting to
libfuzzer are saved in `.cifuzz-corpus` though where that's done is a bit of a mystery to me.

# Regression Flow

## `evaluateExecutionCondition`

Similar to the first execution of this in fuzzing mode, this will look for the first fuzz test to return that it's
enabled then it short circuits and does not check any others.

## `provideArguments`

This will also configure the fuzzing agent, then gather test cases to run from the following sources:

1. A default argument set of just the empty input
2. A set of arguments from the associated resources directory
3. If a `.cifuzz-corpus` directory exists, relevant entries from that are added as well

Prior to returning, the stream of test cases is put through `adaptInputsForFuzzTest` to turn the raw bytes from the
files into the actual types to be given to the tested function.

### Resources Tests

The tests from the resources directory are gathered by `walkInputs`. Which will look
under `resources/<package>/<test class name>Inputs/<test method name>` for tests. It will search for all files
recursively under that directory and use them as test cases, using the file's name as the name of that parameter set and
accepting the file contents as raw bytes. It also accepts .jar files where it will search with the given directory in
the jar.

### CIFuzz Corpus

The corpus kept in `.cifuzz-corpus/<test class name>/<test method name>` holds any inputs that libfuzzer found worth
saving and not necessarily just inputs that caused a crash. I'm not entirely sure what the criteria for this are but
this appears to be something that's entirely managed by libfuzzer's code and not Jazzer.

## `evaluateExecutionCondition`

Unlike the second execution in fuzzing mode, this will allow all fuzz tests to run.

## `interceptTestTemplateMethod`

This will run for each individual test case for each fuzz test and will mostly just allow the test function to proceed
with the provided arguments. Prior to the call to the test, it will enable the agent's hooks and then disable them
afterward. It will also check for and report any findings from Jazzer to JUnit.
