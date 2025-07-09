package com.tangem.hot.sdk.android.jni

internal object TrezorCryptoJNI {

    init {
        System.loadLibrary("TrezorCrypto")
    }

    external fun derive(seed: ByteArray, path: String?, curveName: String): HDNodeJNI
}