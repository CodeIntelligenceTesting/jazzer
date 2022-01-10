# C++ & Java
find -name '*.cpp' -o -name '*.h' -o -name '*.java' | xargs clang-format-13 -i

# Kotlin
# curl -sSLO https://github.com/pinterest/ktlint/releases/download/0.42.1/ktlint && chmod a+x ktlint
ktlint -F "agent/**/*.kt" "driver/**/*.kt" "examples/**/*.kt" "sanitizers/**/*.kt" "tests/**/*.kt"

# BUILD files
# go get github.com/bazelbuild/buildtools/buildifier
buildifier -r .

# Licence headers
# go get -u github.com/google/addlicense
addlicense -c "Code Intelligence GmbH" agent/ bazel/ deploy/ docker/ driver/ examples/ sanitizers/ tests/ *.bzl
