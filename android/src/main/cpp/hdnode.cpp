#include <jni.h>
#include <cstring>
#include <stdexcept>
#include "TrezorCrypto/memzero.h"

extern "C" {
#include "include/TrezorCrypto/bip32.h"
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_tangem_hot_sdk_android_jni_HDNodeJNI_createNative(JNIEnv *_, jclass clazz) {
    return (jlong)(intptr_t) new HDNode();
}

extern "C"
JNIEXPORT void JNICALL
Java_com_tangem_hot_sdk_android_jni_HDNodeJNI_destroyNative(JNIEnv *_, jclass clazz, jlong handle) {
    memzero((HDNode*)(intptr_t)handle, sizeof(HDNode));
    delete (HDNode*)(intptr_t)handle;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_tangem_hot_sdk_android_jni_HDNodeJNI_getDepthNative(JNIEnv *env, jclass clazz, jlong handle) {
    auto node = (HDNode*)(intptr_t)handle;
    return static_cast<jint>(node->depth);
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_tangem_hot_sdk_android_jni_HDNodeJNI_setDepthNative(JNIEnv *env, jclass clazz, jlong handle, jint value) {
    ((HDNode*)(intptr_t)handle)->depth = (uint8_t)value;
    return 0;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_tangem_hot_sdk_android_jni_HDNodeJNI_getChildNum(JNIEnv *env, jclass clazz, jlong handle) {
    auto node = (HDNode*)(intptr_t)handle;
    return static_cast<jint>(node->child_num);
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_tangem_hot_sdk_android_jni_HDNodeJNI_setChildNum(JNIEnv *env, jclass clazz, jlong handle, jint value) {
    ((HDNode*)(intptr_t)handle)->child_num = value;
    return 0;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_tangem_hot_sdk_android_jni_HDNodeJNI_getChainCodeNative(JNIEnv *env, jclass clazz, jlong handle) {
    auto* node = (HDNode*)(intptr_t)handle;
    jbyteArray result = env->NewByteArray(32);
    env->SetByteArrayRegion(result, 0, 32, (const jbyte*)node->chain_code);
    return result;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_tangem_hot_sdk_android_jni_HDNodeJNI_setChainCodeNative(JNIEnv *env, jclass clazz, jlong handle, jbyteArray value) {
    auto* node = (HDNode*)(intptr_t)handle;
    if (env->GetArrayLength(value) != 32) return -1;
    env->GetByteArrayRegion(value, 0, 32, (jbyte*)node->chain_code);
    return 0;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_tangem_hot_sdk_android_jni_HDNodeJNI_getPrivateKeyNative(JNIEnv *env, jclass clazz, jlong handle) {
    auto* node = (HDNode*)(intptr_t)handle;
    jbyteArray result = env->NewByteArray(32);
    env->SetByteArrayRegion(result, 0, 32, (const jbyte*)node->private_key);
    return result;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_tangem_hot_sdk_android_jni_HDNodeJNI_setPrivateKeyNative(JNIEnv *env, jclass clazz, jlong handle, jbyteArray value) {
    auto* node = (HDNode*)(intptr_t)handle;
    if (env->GetArrayLength(value) != 32) return -1;
    env->GetByteArrayRegion(value, 0, 32, (jbyte*)node->private_key);
    return 0;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_tangem_hot_sdk_android_jni_HDNodeJNI_getPublicKeyNative(JNIEnv *env, jclass clazz, jlong handle) {
    HDNode* node = (HDNode*)(intptr_t)handle;
    jbyteArray result = env->NewByteArray(33);
    env->SetByteArrayRegion(result, 0, 33, (const jbyte*)node->public_key);
    return result;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_tangem_hot_sdk_android_jni_HDNodeJNI_setPublicKeyNative(JNIEnv *env, jclass clazz, jlong handle, jbyteArray value) {
    auto* node = (HDNode*)(intptr_t)handle;
    if (env->GetArrayLength(value) != 33) return -1;
    env->GetByteArrayRegion(value, 0, 33, (jbyte*)node->public_key);
    return 0;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_tangem_hot_sdk_android_jni_HDNodeJNI_fingerprint(JNIEnv *env, jobject thiz) {
    jclass hdNodeClass = env->GetObjectClass(thiz);
    jfieldID handleField = env->GetFieldID(hdNodeClass, "nativeHandle", "J");
    jlong handle = env->GetLongField(thiz, handleField);
    auto* node = (HDNode*)(intptr_t)handle;

    auto fingerprint = hdnode_fingerprint(node);
    jbyteArray result = env->NewByteArray(4);
    jbyte fingerprintBytes[4];
    fingerprintBytes[0] = (fingerprint >> 24) & 0xFF;
    fingerprintBytes[1] = (fingerprint >> 16) & 0xFF;
    fingerprintBytes[2] = (fingerprint >> 8) & 0xFF;
    fingerprintBytes[3] = fingerprint & 0xFF;
    env->SetByteArrayRegion(result, 0, 4, fingerprintBytes);
    return result;
}