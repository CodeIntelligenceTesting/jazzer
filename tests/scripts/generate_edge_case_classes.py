#!/usr/bin/env python3
# Copyright 2025 Code Intelligence GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Generate a curated set of Java class files that exercise tricky bytecode features.

Each variant is compiled into its own directory but always uses the fully-qualified
name expected by AsmClassReaderFuzzer (`com.example.Example` by default). This keeps
the seed corpus compatible with the fuzz target's hard-coded loader name while still
covering diverse class-file constructs (records, enums, lambdas, sealed types, etc.).
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple


@dataclass(frozen=True)
class EdgeCaseSource:
    slug: str
    description: str
    template: str


EDGE_CASE_SOURCES: List[EdgeCaseSource] = [
    EdgeCaseSource(
        slug="basic_plain",
        description="Simple verified class with primitive fields and methods.",
        template="""
            __PACKAGE_DECL__

            public class __CLASS_NAME__ {
                public static final int MAGIC = 0xCAFEBABE;

                public int add(int a, int b) {
                    return a + b;
                }

                public long multiply(long a, long b) {
                    return a * b;
                }
            }
        """,
    ),
    EdgeCaseSource(
        slug="annotation_showcase",
        description="Uses runtime-visible annotations and type-use annotations.",
        template="""
            __PACKAGE_DECL__

            import java.lang.annotation.ElementType;
            import java.lang.annotation.Retention;
            import java.lang.annotation.RetentionPolicy;
            import java.lang.annotation.Repeatable;
            import java.lang.annotation.Target;

            @__CLASS_NAME__.Tag(name = "class", weight = 1.0)
            @__CLASS_NAME__.Tag(name = "repeat", weight = 2.0)
            public class __CLASS_NAME__ {
                @Tag(name = "method", weight = 3.5)
                public @Tag(name = "type-use", weight = 4.5) String describe() {
                    return "annotated";
                }

                @Retention(RetentionPolicy.RUNTIME)
                @Target({ElementType.TYPE, ElementType.METHOD, ElementType.TYPE_USE})
                @Repeatable(Tags.class)
                public @interface Tag {
                    String name();

                    double weight();
                }

                @Retention(RetentionPolicy.RUNTIME)
                @Target({ElementType.TYPE, ElementType.METHOD, ElementType.TYPE_USE})
                public @interface Tags {
                    Tag[] value();
                }
            }
        """,
    ),
    EdgeCaseSource(
        slug="record_showcase",
        description="Leverages records with canonical constructors and validation.",
        template="""
            __PACKAGE_DECL__

            public record __CLASS_NAME__(String name, int value) {
                public __CLASS_NAME__ {
                    if (name == null) {
                        name = "default";
                    }
                    value = Math.abs(value);
                }

                public int scaledValue(int factor) {
                    return Math.multiplyExact(value, factor);
                }
            }
        """,
    ),
    EdgeCaseSource(
        slug="enum_state_machine",
        description="Enum with fields, constructors, and interface implementation.",
        template="""
            __PACKAGE_DECL__

            public enum __CLASS_NAME__ implements Runnable {
                INIT(0) {
                    @Override
                    void transition(__CLASS_NAME__ next) {
                        next.run();
                    }
                },
                RUNNING(1),
                STOPPED(2);

                private final int code;

                __CLASS_NAME__(int code) {
                    this.code = code;
                }

                void transition(__CLASS_NAME__ next) {
                    // default no-op
                }

                @Override
                public void run() {
                    switch (this) {
                        case INIT -> transition(RUNNING);
                        case RUNNING -> transition(STOPPED);
                        case STOPPED -> {
                            // terminal state
                        }
                    }
                }

                public int code() {
                    return code;
                }
            }
        """,
    ),
    EdgeCaseSource(
        slug="lambda_playground",
        description="Uses lambdas and method references to trigger invokedynamic.",
        template="""
            __PACKAGE_DECL__

            import java.util.function.Consumer;

            public class __CLASS_NAME__ {
                public Runnable asRunnable(String prefix) {
                    Consumer<String> printer = System.out::println;
                    Runnable runnable = () -> printer.accept(prefix + System.nanoTime());
                    return runnable;
                }
            }
        """,
    ),
    EdgeCaseSource(
        slug="nested_structure",
        description="Creates a nest-host with static and inner members plus enums.",
        template="""
            __PACKAGE_DECL__

            public class __CLASS_NAME__ {
                private int value;

                public __CLASS_NAME__(int value) {
                    this.value = value;
                }

                public int apply(Inner inner) {
                    return inner.bump();
                }

                public static class StaticHelper {
                    public static int negate(int input) {
                        return -input;
                    }
                }

                public final class Inner {
                    public int bump() {
                        value++;
                        return value;
                    }
                }

                private enum State {
                    COLD,
                    WARM,
                    HOT;

                    boolean isTerminal() {
                        return this == HOT;
                    }
                }
            }
        """,
    ),
    EdgeCaseSource(
        slug="interface_defaults",
        description="Interface with private methods, statics, and defaults.",
        template="""
            __PACKAGE_DECL__

            public interface __CLASS_NAME__ {
                default String combine(String lhs, String rhs) {
                    return normalize(lhs) + ":" + normalize(rhs);
                }

                private String normalize(String in) {
                    return in == null ? "" : in.trim();
                }

                static __CLASS_NAME__ noop() {
                    return new __CLASS_NAME__() {
                        @Override
                        public String combine(String lhs, String rhs) {
                            return __CLASS_NAME__.super.combine(lhs, rhs);
                        }
                    };
                }
            }
        """,
    ),
    EdgeCaseSource(
        slug="generics_and_exceptions",
        description="Generic class that throws checked exceptions and uses bridges.",
        template="""
            __PACKAGE_DECL__

            import java.io.IOException;
            import java.util.concurrent.Callable;

            public class __CLASS_NAME__<T extends Number> implements Callable<String> {
                private final T value;

                public __CLASS_NAME__(T value) {
                    this.value = value;
                }

                @Override
                public String call() throws IOException {
                    double raw = value.doubleValue();
                    if (raw < 0) {
                        throw new IOException("negative");
                    }
                    return Double.toString(Math.sqrt(raw));
                }
            }
        """,
    ),
    EdgeCaseSource(
        slug="sealed_hierarchy",
        description="Sealed class with multiple permitted nested subclasses.",
        template="""
            __PACKAGE_DECL__

            public sealed class __CLASS_NAME__ permits __CLASS_NAME__.SubOne, __CLASS_NAME__.SubTwo {
                public int value() {
                    return 42;
                }

                public static final class SubOne extends __CLASS_NAME__ {
                }

                public static final class SubTwo extends __CLASS_NAME__ {
                }
            }
        """,
    ),
    EdgeCaseSource(
        slug="synchronized_blocks",
        description="Uses synchronized methods and blocks to stress monitor bytecodes.",
        template="""
            __PACKAGE_DECL__

            public class __CLASS_NAME__ {
                private static int counter;
                private final Object lock = new Object();

                public __CLASS_NAME__() {
                    counter = (counter + 1) & 0xFFFF;
                }

                public synchronized int incrementSync(int delta) {
                    counter += delta;
                    return counter;
                }

                public int guardedComputation(int base) {
                    synchronized (lock) {
                        counter = Math.max(counter, base);
                        return counter;
                    }
                }
            }
        """,
    ),
    EdgeCaseSource(
        slug="static_init_complex",
        description="Heavy static initializer building tables and literals.",
        template="""
            __PACKAGE_DECL__

            public class __CLASS_NAME__ {
                private static final int[] TABLE;
                private static final String VALUE;

                static {
                    TABLE = new int[16];
                    for (int i = 0; i < TABLE.length; i++) {
                        TABLE[i] = (i * 31) ^ 0xABCD;
                    }
                    VALUE = TABLE[0] + ":" + TABLE[5];
                }

                public String describe() {
                    return VALUE + "/" + TABLE.length;
                }
            }
        """,
    ),
    EdgeCaseSource(
        slug="try_with_resources",
        description="Try-with-resources plus custom AutoCloseable implementations.",
        template="""
            __PACKAGE_DECL__

            import java.io.ByteArrayOutputStream;
            import java.io.IOException;
            import java.nio.charset.StandardCharsets;

            public class __CLASS_NAME__ {
                private static final class Recorder implements AutoCloseable {
                    private final ByteArrayOutputStream baos = new ByteArrayOutputStream();

                    void write(String value) throws IOException {
                        baos.write(value.getBytes(StandardCharsets.UTF_8));
                    }

                    @Override
                    public void close() throws IOException {
                        baos.close();
                    }

                    String data() {
                        return baos.toString(StandardCharsets.UTF_8);
                    }
                }

                public String run(String input) throws IOException {
                    try (Recorder recorder = new Recorder()) {
                        recorder.write(input == null ? "null" : input);
                        recorder.write("|done");
                        return recorder.data();
                    }
                }
            }
        """,
    ),
    EdgeCaseSource(
        slug="varargs_generics",
        description="Generic subclass with @SafeVarargs bridge-style methods.",
        template="""
            __PACKAGE_DECL__

            import java.util.ArrayList;

            public class __CLASS_NAME__ extends ArrayList<String> {
                private static final long serialVersionUID = 1L;

                @SafeVarargs
                public final <T extends CharSequence> void addAllVarargs(T... values) {
                    if (values == null) {
                        return;
                    }
                    for (T value : values) {
                        super.add(value == null ? "" : value.toString());
                    }
                }
            }
        """,
    ),
    EdgeCaseSource(
        slug="switch_expressions",
        description="Switch expressions with arrow labels and default clauses.",
        template="""
            __PACKAGE_DECL__

            public class __CLASS_NAME__ {
                public int score(String state) {
                    return switch (state) {
                        case "INIT" -> 0;
                        case "RUNNING" -> 1;
                        case "STOPPED" -> 2;
                        default -> {
                            yield state == null ? -99 : state.length();
                        }
                    };
                }
            }
        """,
    ),
    EdgeCaseSource(
        slug="pattern_instanceof",
        description="Pattern matching for instanceof and multi-branch logic.",
        template="""
            __PACKAGE_DECL__

            import java.util.List;

            public class __CLASS_NAME__ {
                public int length(Object candidate) {
                    if (candidate instanceof String s && !s.isEmpty()) {
                        return s.length();
                    } else if (candidate instanceof List<?> list && list.size() > 0) {
                        return list.size();
                    } else if (candidate instanceof __CLASS_NAME__ other) {
                        return other.hashCode();
                    }
                    return -1;
                }
            }
        """,
    ),
    EdgeCaseSource(
        slug="method_handles_lookup",
        description="Invokes a private method via MethodHandles lookup/findVirtual.",
        template="""
            __PACKAGE_DECL__

            import java.lang.invoke.MethodHandle;
            import java.lang.invoke.MethodHandles;
            import java.lang.invoke.MethodType;

            public class __CLASS_NAME__ {
                private String greet(String name) {
                    return "hi " + name;
                }

                public String invokeViaMH(String name) throws Throwable {
                    MethodHandles.Lookup lookup = MethodHandles.lookup();
                    MethodType type = MethodType.methodType(String.class, String.class);
                    MethodHandle handle = lookup.findVirtual(__CLASS_NAME__.class, "greet", type);
                    return (String) handle.invoke(this, name);
                }
            }
        """,
    ),
    EdgeCaseSource(
        slug="var_handle_access",
        description="VarHandle access to a private field with atomic operations.",
        template="""
            __PACKAGE_DECL__

            import java.lang.invoke.MethodHandles;
            import java.lang.invoke.VarHandle;

            public class __CLASS_NAME__ {
                private int value;
                private static final VarHandle VALUE_HANDLE;

                static {
                    try {
                        VALUE_HANDLE = MethodHandles.lookup().findVarHandle(__CLASS_NAME__.class, "value", int.class);
                    } catch (ReflectiveOperationException e) {
                        throw new ExceptionInInitializerError(e);
                    }
                }

                public int incrementAndGet() {
                    return (int) VALUE_HANDLE.getAndAdd(this, 1) + 1;
                }
            }
        """,
    ),
    EdgeCaseSource(
        slug="anonymous_classes",
        description="Creates anonymous inner classes and lambdas capturing state.",
        template="""
            __PACKAGE_DECL__

            import java.util.concurrent.Callable;
            import java.util.function.Supplier;

            public class __CLASS_NAME__ {
                public Callable<String> makeCallable(String value) {
                    return new Callable<>() {
                        @Override
                        public String call() {
                            return value + ":" + System.nanoTime();
                        }
                    };
                }

                public Supplier<String> makeSupplier(String prefix) {
                    return () -> prefix + "-supplier";
                }
            }
        """,
    ),
    EdgeCaseSource(
        slug="exception_hierarchy",
        description="Custom checked exception with multi-catch propagation.",
        template="""
            __PACKAGE_DECL__

            public class __CLASS_NAME__ extends Exception {
                private static final long serialVersionUID = 1L;

                public __CLASS_NAME__(String message) {
                    super(message);
                }

                public void doWork() throws __CLASS_NAME__ {
                    try {
                        risky();
                    } catch (IllegalStateException | IllegalArgumentException ex) {
                        throw new __CLASS_NAME__(ex.getMessage());
                    }
                }

                private void risky() {
                    if ((System.nanoTime() & 1) == 0) {
                        throw new IllegalStateException("even");
                    }
                }
            }
        """,
    ),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate and compile Java sources that exercise diverse class file features "
            "while keeping a consistent fully-qualified class name."
        )
    )
    parser.add_argument(
        "output_dir",
        type=Path,
        help="Directory that should receive the compiled .class files.",
    )
    parser.add_argument(
        "--javac",
        default="javac",
        help="Path to the javac executable to use (default: %(default)s).",
    )
    parser.add_argument(
        "--release",
        default="17",
        help="Compile with --release (default: %(default)s). Use 21+ for preview features.",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove the output directory before copying newly compiled classes.",
    )
    parser.add_argument(
        "--class-name",
        default="com.example.Example",
        help="Fully-qualified class name each variant should use (default: %(default)s).",
    )
    return parser.parse_args()


def split_class_name(fqcn: str) -> Tuple[str, str]:
    parts = fqcn.rsplit(".", 1)
    if len(parts) == 1:
        package_name = ""
        class_name = parts[0]
    else:
        package_name, class_name = parts
    if not class_name:
        raise ValueError(f"Invalid class name: '{fqcn}'")
    return package_name, class_name


def package_to_path(package_name: str) -> Path:
    if not package_name:
        return Path()
    return Path(*package_name.split("."))


def render_source(template: str, package_name: str, class_name: str) -> str:
    package_decl = f"package {package_name};" if package_name else ""
    rendered = textwrap.dedent(template).strip()
    rendered = rendered.replace("__PACKAGE_DECL__", package_decl)
    rendered = rendered.replace("__CLASS_NAME__", class_name)
    return rendered + "\n"


def write_case_source(
    case: EdgeCaseSource, src_root: Path, package_name: str, class_name: str
) -> Path:
    relative_dir = package_to_path(package_name)
    target_dir = src_root / relative_dir
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{class_name}.java"
    contents = render_source(case.template, package_name, class_name)
    target.write_text(contents, encoding="utf-8")
    return target


def compile_sources(
    javac: str, release: str, sources: List[Path], classes_dir: Path
) -> None:
    cmd = [
        javac,
        "-g:none",
        "-XDignore.symbol.file",
        "-Werror",
        "-Xlint:all",
        "-d",
        str(classes_dir),
        "--release",
        str(release),
        *[str(src) for src in sources],
    ]
    subprocess.run(cmd, check=True)


def copy_classes(source_dir: Path, dest_dir: Path) -> None:
    for path in source_dir.rglob("*"):
        if path.is_file():
            rel = path.relative_to(source_dir)
            target = dest_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)


def main() -> None:
    args = parse_args()
    output_dir: Path = args.output_dir.resolve()
    package_name, class_name = split_class_name(args.class_name)

    if args.clean and output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    built_variants = []
    with tempfile.TemporaryDirectory(prefix="class-edgecases-") as tmp:
        tmp_path = Path(tmp)
        for case in EDGE_CASE_SOURCES:
            case_src_root = tmp_path / case.slug / "src"
            case_classes_dir = tmp_path / case.slug / "classes"
            case_src_root.mkdir(parents=True, exist_ok=True)
            case_classes_dir.mkdir(parents=True, exist_ok=True)

            source_path = write_case_source(case, case_src_root, package_name, class_name)

            try:
                compile_sources(args.javac, args.release, [source_path], case_classes_dir)
            except subprocess.CalledProcessError as exc:
                print(f"javac failed while compiling '{case.slug}': {exc}", file=sys.stderr)
                sys.exit(exc.returncode)

            destination = output_dir / case.slug
            destination.mkdir(parents=True, exist_ok=True)
            copy_classes(case_classes_dir, destination)
            built_variants.append((case.slug, case.description, destination))

    print(f"Wrote {len(built_variants)} edge-case variants using class name '{args.class_name}'.")
    for slug, desc, dest in built_variants:
        print(f"- {slug}: {desc} -> {dest}")


if __name__ == "__main__":
    main()
