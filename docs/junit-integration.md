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

JUnit will call the following methods for each test marked with `FuzzTest`.

## `evaluateExecutionCondition`

The first call to this test will determine if the test should be run at all. In fuzzing mode, we only allow one test to
be run due to global state in libfuzzer that would mean multiple tests would interfere with each other. Jazzer will
accept the first fuzz test that is checked as the test to be run. It will cache which test it has seen first and
return that test as enabled.

If this returns that a test is disabled, JUnit will not run the rest of these methods for this test and instead skip
to the next one.

## `provideArguments`

This will configure the fuzzing agent to set up code instrumentation, instantiate a `FuzzTestExecutor` and put it into
JUnit's `extensionContext`, then create a stream of a single empty argument set. As the comment mentions, this is so
that JUnit will actually execute the test but the argument will not be used.

## `evaluateExecutionCondition`

This will be called for each argument set for the current test. In fuzzing mode, there will only be the single
empty argument set which will be enabled.

## `interceptTestTemplateMethod`

This will call `invocation.skip()` which prevents invoking the test function with the default set of
arguments `provideArguments` created. It will instead extract the `FuzzTestExecutor` instance from
the `extensionContext` and then calls `FuzzTestExecutor#execute` which creates a `FuzzTargetRunner` to run the actual
fuzzing.

Crashes are saved in `resources/<package>/<test file name>Inputs/<test method name>` and results that are interesting to
libfuzzer are saved in `.cifuzz-corpus`.

# Regression Flow

Similar to fuzzing mode, JUnit will call these methods for each test marked with `FuzzTest`.

## `evaluateExecutionCondition`

This checks if the given test should be run at all. In regression mode, all tests are run so this will always return
enabled.

## `provideArguments`

This will configure the fuzzing agent as in fuzzing mode, then gather test cases to run from the following sources:

1. A default argument set of just an empty input
2. A set of arguments from the associated resources directory
3. If a `.cifuzz-corpus` directory exists, relevant entries from that are added as well

Prior to returning, the stream of test cases is put through `adaptInputsForFuzzTest` to turn the raw bytes from the
files into the actual types to be given to the tested function.

### Resources Tests

The tests from the resources directory are gathered by `walkInputs`. This will look for inputs in two places:
- `resources/<package>/<test class name>Inputs` - files found directly within this directory will be used as inputs for 
  any tests within this class. This allows for easy sharing of corpus entries. Jazzer does not automatically put entries
  here, instead a human will need to decide a finding should be shared and manually move it.
- `resources/<package>/<test class name>Inputs/<test method name>` - files found in this directory and any directory
  under it are used as inputs for only the test of the same name.

JUnit will use the file's name as the name of the test case for its reporting. It also accepts .jar files where it will
search with the given directory in the jar.

### CIFuzz Corpus

The corpus kept in `.cifuzz-corpus/<test class name>/<test method name>` holds any inputs that libfuzzer found worth
saving and not necessarily just inputs that caused a crash. Jazzer is able to set the directory but the contents of
these directories are managed entirely by libfuzzer. Unlike with the resources test inputs above, this will not look
in `.cifuzz-corpus/<test class name>` for shared test cases. This is a limitation of libfuzzer.

## `evaluateExecutionCondition`

This will run once per argument set returned by `provideArguments` for this test. All argument sets will return as
enabled.

## `interceptTestTemplateMethod`

This will run for each individual test case for each fuzz test and will mostly just allow the test function to proceed
with the provided arguments. Prior to the call to the test, it will enable the agent's hooks and then disable them
afterward. It will also check for and report any findings from Jazzer to JUnit.

# Diagrams

Below are two sequence diagrams for how JUnit calls `evaluateExecutionConditions` and `provideArguments` in fuzzing and
regression mode. These diagrams ignore `interceptTestTemplateMethod` for brevity as its behavior and place in the
sequence is more clear.

## Fuzzing

![created on sequencediagram.org, load the svg in the editor to edit](./images/fuzzing-flow.svg)

## Regression

![created on sequencediagram.org, load the svg in the editor to edit](./images/regression-flow.svg)
