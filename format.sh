# C++ & Java
find -name '*.cpp' -o -name '*.c' -o -name '*.h' -o -name '*.java' | xargs clang-format-13 -i

# Kotlin
# curl -sSLO https://github.com/pinterest/ktlint/releases/download/0.42.1/ktlint && chmod a+x ktlint
ktlint -F "examples/**/*.kt" "sanitizers/**/*.kt" "src/**/*.kt" "tests/**/*.kt"

# BUILD files
# go get github.com/bazelbuild/buildtools/buildifier
buildifier -r .

# Licence headers
# go get -u github.com/google/addlicense
addlicense -c "Code Intelligence GmbH" bazel/ deploy/ docker/ examples/ sanitizers/ src/ tests/ *.bzl
