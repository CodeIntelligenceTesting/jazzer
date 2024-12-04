// Copyright 2024 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/* This file was originally generated by cc_jni_library(name =
   jazzer_fuzzed_data_provider_impl) and copied here and modified

   Specifically it was taken from
   `bazel-bin/src/main/java/com/code_intelligence/jazzer/driver/fuzzed_data_provider_impl.hdrs.h/com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl.h`
   and modified such that all symbol names now include `selffuzz` in order to
   be usable by our selffuzzing library. Due to the shading of our class files,
   the selffuzz code will attempt to load symbols with the new classpath which
   otherwise don't exist.

   Normally the built jazzer jar will have a dylib (on Mac) in
   `/com/code_intelligence/jazzer/driver/jazzer_fuzzed_data_provider_macos_aarch64/libjazzer_fuzzed_data_provider.dylib`

   FuzzedDataProviderImpl will load that with a call to
   ```
       RulesJni.loadLibrary("jazzer_fuzzed_data_provider",
   "/com/code_intelligence/jazzer/driver");
   ```
   which will look in a folder with that name plus architecture-specific bits
   for a library to load.

   Our shading utility properly changes that into
   ```
       RulesJni.loadLibrary("jazzer_fuzzed_data_provider",
   "/com/code_intelligence/selffuzz/jazzer/driver");
   ```
   which is where that lib will be in the new jar and the shaded
   FuzzedDataProviderImpl will load it but that library is not changed during
   the shading so it will have the symbols defined at build time. When
   FuzzedDataProviderImpl attempts to call
   `Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_nativeInit`,
   it will fail because the symbol does not exist.

   Duplicating and renaming the symbols via this header file and copying and
   renaming `nativeInit` in `fuzzed_data_provider.cpp` means that both the
   normal and shaded FuzzedDataProviderImpls will be able to work. It would
   probably be possible to remove this with some more selective build rules when
   building a selffuzz jar.
*/
#include <jni.h>
/* Header for class com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 */

#ifndef _Included_com_code_intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl
#define _Included_com_code_intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    nativeInit
 * Signature: ()V
 */
JNIEXPORT void JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_nativeInit(
    JNIEnv *, jclass);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeBoolean
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeBoolean(
    JNIEnv *, jobject);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeBooleans
 * Signature: (I)[Z
 */
JNIEXPORT jbooleanArray JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeBooleans(
    JNIEnv *, jobject, jint);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeByte
 * Signature: ()B
 */
JNIEXPORT jbyte JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeByte(
    JNIEnv *, jobject);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeShort
 * Signature: ()S
 */
JNIEXPORT jshort JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeShort(
    JNIEnv *, jobject);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeShorts
 * Signature: (I)[S
 */
JNIEXPORT jshortArray JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeShorts(
    JNIEnv *, jobject, jint);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeInt
 * Signature: ()I
 */
JNIEXPORT jint JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeInt(
    JNIEnv *, jobject);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeInts
 * Signature: (I)[I
 */
JNIEXPORT jintArray JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeInts(
    JNIEnv *, jobject, jint);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeLong
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeLong(
    JNIEnv *, jobject);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeLongs
 * Signature: (I)[J
 */
JNIEXPORT jlongArray JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeLongs(
    JNIEnv *, jobject, jint);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeFloat
 * Signature: ()F
 */
JNIEXPORT jfloat JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeFloat(
    JNIEnv *, jobject);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeRegularFloat
 * Signature: ()F
 */
JNIEXPORT jfloat JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeRegularFloat(
    JNIEnv *, jobject);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeProbabilityFloat
 * Signature: ()F
 */
JNIEXPORT jfloat JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeProbabilityFloat(
    JNIEnv *, jobject);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeDouble
 * Signature: ()D
 */
JNIEXPORT jdouble JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeDouble(
    JNIEnv *, jobject);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeRegularDouble
 * Signature: ()D
 */
JNIEXPORT jdouble JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeRegularDouble(
    JNIEnv *, jobject);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeProbabilityDouble
 * Signature: ()D
 */
JNIEXPORT jdouble JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeProbabilityDouble(
    JNIEnv *, jobject);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeChar
 * Signature: ()C
 */
JNIEXPORT jchar JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeChar(
    JNIEnv *, jobject);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeCharNoSurrogates
 * Signature: ()C
 */
JNIEXPORT jchar JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeCharNoSurrogates(
    JNIEnv *, jobject);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeAsciiString
 * Signature: (I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeAsciiString(
    JNIEnv *, jobject, jint);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeString
 * Signature: (I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeString(
    JNIEnv *, jobject, jint);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeRemainingAsAsciiString
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeRemainingAsAsciiString(
    JNIEnv *, jobject);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeRemainingAsString
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeRemainingAsString(
    JNIEnv *, jobject);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeBytes
 * Signature: (I)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeBytes(
    JNIEnv *, jobject, jint);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeRemainingAsBytes
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeRemainingAsBytes(
    JNIEnv *, jobject);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    remainingBytes
 * Signature: ()I
 */
JNIEXPORT jint JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_remainingBytes(
    JNIEnv *, jobject);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeByteUnchecked
 * Signature: (BB)B
 */
JNIEXPORT jbyte JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeByteUnchecked(
    JNIEnv *, jobject, jbyte, jbyte);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeShortUnchecked
 * Signature: (SS)S
 */
JNIEXPORT jshort JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeShortUnchecked(
    JNIEnv *, jobject, jshort, jshort);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeCharUnchecked
 * Signature: (CC)C
 */
JNIEXPORT jchar JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeCharUnchecked(
    JNIEnv *, jobject, jchar, jchar);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeIntUnchecked
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeIntUnchecked(
    JNIEnv *, jobject, jint, jint);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeLongUnchecked
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeLongUnchecked(
    JNIEnv *, jobject, jlong, jlong);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeRegularFloatUnchecked
 * Signature: (FF)F
 */
JNIEXPORT jfloat JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeRegularFloatUnchecked(
    JNIEnv *, jobject, jfloat, jfloat);

/*
 * Class:     com_code_intelligence_jazzer_driver_FuzzedDataProviderImpl
 * Method:    consumeRegularDoubleUnchecked
 * Signature: (DD)D
 */
JNIEXPORT jdouble JNICALL
Java_com_code_1intelligence_selffuzz_jazzer_driver_FuzzedDataProviderImpl_consumeRegularDoubleUnchecked(
    JNIEnv *, jobject, jdouble, jdouble);

#ifdef __cplusplus
}
#endif
#endif
