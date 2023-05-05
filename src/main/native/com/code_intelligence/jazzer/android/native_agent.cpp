#include <sstream>
#include <memory>
#include <map>
#include <iostream>
#include <dlfcn.h>
#include <string>
#include <vector>
#include <unordered_set>
#include <stdio.h>

#include <jni.h>
#include "jvmti.h"
#include "slicer/reader.h"
#include "slicer/writer.h"
#include "slicer/arrayview.h"
#include "slicer/dex_format.h"
#include "jazzer_jvmti_allocator.h"
#include "dex_file_manager.h"
#include "absl/strings/str_split.h"

static std::string agentOptions;
static DexFileManager dfm;

const std::string kAndroidAgentClass = "com/code_intelligence/jazzer/android/DexFileManager";

void retransformLoadedClasses(jvmtiEnv* jvmti, JNIEnv* env){

    jint classCount = 0;
    jclass* classes;

    jvmti->GetLoadedClasses(&classCount, &classes);

    std::vector<jclass> classesToRetransform;
    for(int i = 0; i < classCount; i++){
        jboolean isModifiable = false;
        jvmti->IsModifiableClass(classes[i], &isModifiable);

        if((bool)isModifiable){
            classesToRetransform.push_back(classes[i]);
        }
    }

    jvmtiError errorNum = jvmti->RetransformClasses(classesToRetransform.size(), &classesToRetransform[0]);
    if(errorNum != JVMTI_ERROR_NONE){
        std::cout << "Could not retransform classes. JVMTI error: " << errorNum << std::endl;
        exit(1); 
    }
}

std::vector<std::string> getDexFiles(std::string jarPath, JNIEnv* env){
    jclass jazzerClass = env->FindClass(kAndroidAgentClass.c_str());
    if(jazzerClass == nullptr){
        std::cout << kAndroidAgentClass << " could not be found" << std::endl;
        exit(1);
    }

    const char* getDexFilesFunction = "getDexFilesForJar";
    jmethodID getDexFilesForJar = env->GetStaticMethodID(jazzerClass, getDexFilesFunction, "(Ljava/lang/String;)[Ljava/lang/String;");
    if(getDexFilesForJar == nullptr){
        std::cout << getDexFilesFunction << " could not be found\n";
        exit(1);
    }

    jstring jJarFile = env->NewStringUTF(jarPath.data());
    jobjectArray dexFilesArray = (jobjectArray)env->CallStaticObjectMethod(jazzerClass, getDexFilesForJar, jJarFile);
    int length = env->GetArrayLength(dexFilesArray);

    std::vector<std::string> dexFilesResult;
    for(int i = 0; i < length; i++){
        jstring dexFileJstring = (jstring)env->GetObjectArrayElement(dexFilesArray, i);
        const char* dexFileChars = env->GetStringUTFChars(dexFileJstring, NULL);
        std::string dexFileString(dexFileChars);

        env->ReleaseStringUTFChars(dexFileJstring, dexFileChars);
        dexFilesResult.push_back(dexFileString);
    }

    return dexFilesResult;
}

void initializeBootclassOverrideJar(std::string jarPath, JNIEnv* env){
    std::vector<std::string> dexFiles = getDexFiles(jarPath, env);

    std::cout << "Adding DEX files for: " << jarPath << std::endl;
    for(int i = 0; i < dexFiles.size(); i++){
        std::cout << "DEX FILE: " << dexFiles[i] << std::endl;
    }

    for(int i = 0; i < dexFiles.size(); i++){
        std::cout << "Processing DEX File: " << dexFiles[i] << std::endl;
        jclass bootHelperClass = env->FindClass(kAndroidAgentClass.c_str());
        if(bootHelperClass == nullptr){
            std::cout << kAndroidAgentClass <<" could not be found" << std::endl;
            exit(1);
        }

        jmethodID getBytecodeFromDex = env->GetStaticMethodID(bootHelperClass, "getBytecodeFromDex", "(Ljava/lang/String;Ljava/lang/String;J)[B");
        if(getBytecodeFromDex == nullptr){
            std::cout << "'getBytecodeFromDex' not found\n";
            exit(1);
        }

        jstring jjarPath = env->NewStringUTF(jarPath.data());
        jstring jdexFile = env->NewStringUTF(dexFiles[i].data());
        jlong joffset = (jint)0;

        int length = 1;
        std::vector<unsigned char> dexFileBytes;
        while(length > 0){
            jbyteArray dexBytes = (jbyteArray)env->CallStaticObjectMethod(bootHelperClass, getBytecodeFromDex, jjarPath, jdexFile, joffset);

            if(env->ExceptionCheck()){
                env->ExceptionDescribe();
                exit(1);
            }

            jbyte *data = new jbyte;
            data = env->GetByteArrayElements(dexBytes, 0);
            length = env->GetArrayLength(dexBytes);

            for(int j = 0; j < length; j++){
                dexFileBytes.push_back(data[j]);
            }

            joffset += length;
            env->DeleteLocalRef(dexBytes);
        }

        env->DeleteLocalRef(jjarPath);
        env->DeleteLocalRef(jdexFile);
        env->DeleteLocalRef(bootHelperClass);

        unsigned char *usData = reinterpret_cast<unsigned char*>(&dexFileBytes[0]);
        dfm.addDexFile(usData, (int)joffset);
    }
}

void JNICALL jazzerClassFileLoadHook(
            jvmtiEnv* jvmti,
            JNIEnv* jni_env,
            jclass class_being_redefined,
            jobject loader,
            const char* name,
            jobject protection_domain,
            jint class_data_len,
            const unsigned char* class_data,
            jint* new_class_data_len,
            unsigned char** new_class_data){

    int indx = dfm.findDexFileForClass(name);
    if(indx < 0){
        return;
    }
    
    size_t newSize;
    unsigned char* newClassDataResult = dfm.getClassBytes(name, indx, jvmti, &newSize);
    
    dex::Reader oldReader(const_cast<unsigned char*>(class_data), (size_t)class_data_len);
    dex::Reader newReader(newClassDataResult, newSize);
    if(dfm.structureMatches(&oldReader, &newReader, name)) {
        std::cout << "REDEFINING WITH INSTRUMENTATION:  " << name << std::endl;
        *new_class_data = newClassDataResult;
        *new_class_data_len = static_cast<jint>(newSize);
    }
}

bool fileExists(std::string filePath){
    FILE *fp;
    fp = fopen(filePath.c_str(), "r");
    bool found = fp != NULL;

    if(found){
        fclose(fp);
    }

    return found;
}

void JNICALL jazzerVMInit(jvmtiEnv *jvmti_env, JNIEnv* jni_env, jthread thread){
    // Parse agentOptions

    std::stringstream ss(agentOptions);
    std::string token;

    std::string jazzerClassesJar;
    std::vector<std::string> bootpathClassesOverrides;
    while(std::getline(ss, token, ',')){
        std::vector<std::string> split = absl::StrSplit(token, absl::MaxSplits('=', 1));
        if(split.size() < 2){
            std::cout << "Error processing option in native agent: " << token;
            exit(1);
        }

        if(split[0] == "injectJars"){
            jazzerClassesJar = split[1];
        } else if (split[0] == "bootstrapClassOverrides"){
            bootpathClassesOverrides = absl::StrSplit(split[1], absl::MaxSplits(':', 10));
        }
    }

    if(!fileExists(jazzerClassesJar)){
        std::cout << "ERROR: Jazzer bootstrap class file not found at: " << jazzerClassesJar << std::endl;
        exit(1);
    }

    jvmti_env->AddToBootstrapClassLoaderSearch(jazzerClassesJar.c_str());

    jvmtiCapabilities jazzerJvmtiCapabilities = {
        .can_tag_objects = 0,
        .can_generate_field_modification_events = 0,
        .can_generate_field_access_events = 0,
        .can_get_bytecodes = 0,
        .can_get_synthetic_attribute = 0,
        .can_get_owned_monitor_info = 0,
        .can_get_current_contended_monitor = 0,
        .can_get_monitor_info = 0,
        .can_pop_frame = 0,                 // <-
        .can_redefine_classes = 1,
        .can_signal_thread = 0,
        .can_get_source_file_name = 1,
        .can_get_line_numbers = 0,
        .can_get_source_debug_extension = 0,
        .can_access_local_variables = 0,
        .can_maintain_original_method_order = 0,
        .can_generate_single_step_events = 0,
        .can_generate_exception_events = 0,
        .can_generate_frame_pop_events = 0,
        .can_generate_breakpoint_events = 0,
        .can_suspend = 0,
        .can_redefine_any_class = 0,
        .can_get_current_thread_cpu_time = 0,
        .can_get_thread_cpu_time = 0,
        .can_generate_method_entry_events = 0,
        .can_generate_method_exit_events = 0,
        .can_generate_all_class_hook_events = 0,
        .can_generate_compiled_method_load_events = 0,
        .can_generate_monitor_events = 0,
        .can_generate_vm_object_alloc_events = 0,
        .can_generate_native_method_bind_events = 0,
        .can_generate_garbage_collection_events = 0,
        .can_generate_object_free_events = 0,
        .can_force_early_return = 0,
        .can_get_owned_monitor_stack_depth_info = 0,
        .can_get_constant_pool = 0,
        .can_set_native_method_prefix = 0,
        .can_retransform_classes = 1,
        .can_retransform_any_class = 0,
        .can_generate_resource_exhaustion_heap_events = 0,
        .can_generate_resource_exhaustion_threads_events = 0,
    };

    jvmtiError je = jvmti_env->AddCapabilities(&jazzerJvmtiCapabilities);
    if(je != JVMTI_ERROR_NONE){
        std::cout << "JVMTI ERROR: " << je << std::endl;
        exit(1);
    }

    for(int i = 0; i < bootpathClassesOverrides.size(); i++){
        if(!fileExists(bootpathClassesOverrides[i])){
            std::cout << "ERROR: Bootpath Class override jar not found at: " << bootpathClassesOverrides[i] << std::endl;
            exit(1);
        }

        initializeBootclassOverrideJar(bootpathClassesOverrides[i], jni_env);
    }

    retransformLoadedClasses(jvmti_env, jni_env);
}

JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM* vm, char* options, void* reserved) {
    jvmtiEnv* jvmti = nullptr;
    if (vm->GetEnv((void**)&jvmti, JVMTI_VERSION_1_2) != JNI_OK) {
        return 1;
    }

    jvmtiEventCallbacks callbacks;

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.ClassFileLoadHook = jazzerClassFileLoadHook;
    callbacks.VMInit = jazzerVMInit;

    jvmti->SetEventCallbacks(&callbacks, sizeof(jvmtiEventCallbacks));
    jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, NULL);
    jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_INIT, NULL);

    // Save the options string here, this is the only time it will be available
    // however, we wont be able to use this to initialize until VMInit callback is called
    agentOptions = std::string(options);
    return 0;
}



