#include <jni.h>
#include <cstring>
#include <stdexcept>
#include <string>
#include "DerivationPath.cpp"
#include "TrezorCrypto/TrezorCrypto.h"
#include "TrezorCrypto/cardano.h"

#define MNEMONIC_BUF_SIZE 256
#define SEED_BUF_SIZE 64

#define CARDANO_SECRET_LEN 96

extern "C" {
#include "include/TrezorCrypto/bip32.h"
}

static void throwJava(JNIEnv *env, const char *className, const char *msg) {
    jclass ex = env->FindClass(className);
    if (ex) env->ThrowNew(ex, msg ? msg : "");
}

jobject hdnode_to_java(JNIEnv *env, const HDNode *node) {
    jclass hdNodeClass = env->FindClass("com/tangem/hot/sdk/android/jni/HDNodeJNI");
    jmethodID constructor = env->GetMethodID(hdNodeClass, "<init>", "(J)V");
    auto handle = (jlong) (intptr_t) node;
    jobject hdNodeObject = env->NewObject(hdNodeClass, constructor, handle);
    return hdNodeObject;
}

HDNode *hdnode_from_java(JNIEnv *env, jobject hdNodeObject) {
    jclass hdNodeClass = env->GetObjectClass(hdNodeObject);
    jfieldID handleField = env->GetFieldID(hdNodeClass, "nativeHandle", "J");
    jlong handle = env->GetLongField(hdNodeObject, handleField);

    if (handle == 0) {
        throwJava(env, "java/lang/NullPointerException",
                  "Native handle is null in hdnode_from_java");
    }

    return (HDNode *) (intptr_t) handle;
}

bool entropy_to_seed(const uint8_t *entropy, int entropy_len, const char *passphrase,
                     uint8_t out_seed[SEED_BUF_SIZE]) {
    char mnemonic[MNEMONIC_BUF_SIZE] = {0};
    const char* res = mnemonic_from_data(entropy, entropy_len, mnemonic, MNEMONIC_BUF_SIZE);
    if (!res) {
        memzero(mnemonic, sizeof(mnemonic));
        return false;
    }
    mnemonic_to_seed(mnemonic, passphrase ? passphrase : "", out_seed, nullptr);
    memzero(mnemonic, sizeof(mnemonic));
    return true;
}

extern "C"
JNIEXPORT jobject JNICALL
Java_com_tangem_hot_sdk_android_jni_TrezorCryptoJNI_masterHdNode(JNIEnv *env, jobject thiz,
                                                                 jbyteArray entropy,
                                                                 jbyteArray passphrase,
                                                                 jstring curve_name) {

    auto entropyBytes = reinterpret_cast<const uint8_t *>(
            env->GetByteArrayElements(entropy, nullptr)
    );
    int entropyLength = env->GetArrayLength(entropy);

    jsize pass_len = env->GetArrayLength(passphrase);
    std::vector<uint8_t> pass(static_cast<size_t>(pass_len));
    env->GetByteArrayRegion(passphrase, 0, pass_len, reinterpret_cast<jbyte*>(pass.data()));
    const char* pass_cstr = reinterpret_cast<const char*>(pass.data());

    const char *curveNameStr = env->GetStringUTFChars(curve_name, nullptr);
    auto seedNode = new HDNode();

    if (strcmp(curveNameStr, ED25519_CARDANO_NAME) == 0) {
        uint8_t secret[CARDANO_SECRET_LEN] = {0};
        secret_from_entropy_cardano_icarus(reinterpret_cast<const uint8_t *>(pass_cstr),
                                           static_cast<int>(pass_len), entropyBytes,
                                           entropyLength, secret, nullptr);

        hdnode_from_secret_cardano(secret, seedNode);
        memzero(secret, CARDANO_SECRET_LEN);
    } else {
        uint8_t seed[SEED_BUF_SIZE] = {0};
        entropy_to_seed(entropyBytes, entropyLength, pass_cstr, seed);
        hdnode_from_seed(
                seed,
                SEED_BUF_SIZE,
                curveNameStr,
                seedNode
        );
        memzero(seed, SEED_BUF_SIZE);
    }

    hdnode_fill_public_key(seedNode);

    env->ReleaseStringUTFChars(curve_name, curveNameStr);

    return hdnode_to_java(env, seedNode);
}

extern "C"
JNIEXPORT jobject JNICALL
Java_com_tangem_hot_sdk_android_jni_TrezorCryptoJNI_deriveHdNode(JNIEnv *env, jobject thiz,
                                                                 jobject hd_node_jni,
                                                                 jstring path) {

    auto seed_node = hdnode_from_java(env, hd_node_jni);
    auto out_node = new HDNode();
    memcpy(out_node, seed_node, sizeof(HDNode));
    hdnode_fill_public_key(out_node);

    if (path == nullptr) {
        return hdnode_to_java(env, out_node);
    }

    const char *pathStr = env->GetStringUTFChars(path, nullptr);
    std::string derivationPathStr(pathStr);
    env->ReleaseStringUTFChars(path, pathStr);

    if (derivationPathStr.empty()) {
        return hdnode_to_java(env, out_node);
    }

    auto derivedNode = out_node;
    auto derivationPath = DerivationPath(derivationPathStr);
    for (const auto &index: derivationPath.indices) {
        hdnode_private_ckd(derivedNode, index.derivationIndex());
    }

    hdnode_fill_public_key(out_node);

    return hdnode_to_java(env, out_node);
}


extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_tangem_hot_sdk_android_jni_TrezorCryptoJNI_signMessage(JNIEnv *env, jobject thiz,
                                                                jobject hd_node_jni,
                                                                jbyteArray message) {

    auto node = hdnode_from_java(env, hd_node_jni);
    auto messageBytes = reinterpret_cast<const uint8_t *>(env->GetByteArrayElements(message,
                                                                                    nullptr));
    uint32_t messageLength = env->GetArrayLength(message);
    uint8_t signature[64] = {0};
    uint8_t recoveryByte = 0;

    int result;
    if (node->curve->params) {
        result = hdnode_sign_digest(node, messageBytes, signature, &recoveryByte, nullptr);
    } else {
        result = hdnode_sign(node, messageBytes, messageLength, static_cast<HasherType>(0), signature, &recoveryByte, nullptr);
    }

    env->ReleaseByteArrayElements(message, (jbyte *) messageBytes, 0);
    if (result != 0) {
        throwJava(env, "java/lang/RuntimeException",
                  "Failed to sign message with HDNode");
    }
    jbyteArray signatureArray = env->NewByteArray(64);
    if (signatureArray == nullptr) {
        throwJava(env, "java/lang/OutOfMemoryError",
                  "Failed to allocate byte array for signature");
        return nullptr;
    }
    env->SetByteArrayRegion(signatureArray, 0, 64, (const jbyte *) signature);
    return signatureArray;
}