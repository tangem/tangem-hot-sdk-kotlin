#include <jni.h>
#include <cstring>
#include <stdexcept>
#include <string>
#include "DerivationPath.cpp"

extern "C" {
#include "include/TrezorCrypto/bip32.h"
}

jobject hdnode_to_java(JNIEnv *env, const HDNode *node) {
    jclass hdNodeClass = env->FindClass("com/tangem/hot/sdk/android/jni/HDNodeJNI");
    jmethodID constructor = env->GetMethodID(hdNodeClass, "<init>", "(J)V");
    auto handle = (jlong) (intptr_t) node;
    jobject hdNodeObject = env->NewObject(hdNodeClass, constructor, handle);
    return hdNodeObject;
}

extern "C"
JNIEXPORT jobject JNICALL
Java_com_tangem_hot_sdk_android_jni_TrezorCryptoJNI_derive(JNIEnv *env, jobject _,
                                                           jbyteArray seed, jstring path,
                                                           jstring curve_name) {

    jbyte* seedBytes = env->GetByteArrayElements(seed, nullptr);
    const char* curveNameStr = env->GetStringUTFChars(curve_name, nullptr);

    auto* seedNode = new HDNode();
    hdnode_from_seed(
            reinterpret_cast<const uint8_t*>(seedBytes),
            env->GetArrayLength(seed),
            curveNameStr,
            seedNode
    );

    env->ReleaseByteArrayElements(seed, seedBytes, JNI_ABORT);
    env->ReleaseStringUTFChars(curve_name, curveNameStr);

    if (path == nullptr) {
        return hdnode_to_java(env, seedNode);
    }

    const char* pathStr = env->GetStringUTFChars(path, nullptr);
    std::string derivationPathStr(pathStr);
    env->ReleaseStringUTFChars(path, pathStr);

    if (derivationPathStr.empty()) {
        return hdnode_to_java(env, seedNode);
    }

    auto derivedNode = seedNode;
    auto derivationPath = DerivationPath(derivationPathStr);
    for (const auto &index : derivationPath.indices) {
        hdnode_private_ckd(derivedNode, index.derivationIndex());
    }

    return hdnode_to_java(env, derivedNode);
}