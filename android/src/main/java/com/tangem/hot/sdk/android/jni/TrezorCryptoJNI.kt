package com.tangem.hot.sdk.android.jni

internal object TrezorCryptoJNI {

    init {
        System.loadLibrary("TrezorCrypto")
    }

    external fun masterHdNode(entropy: ByteArray, passphrase: ByteArray, curveName: String): HDNodeJNI

    external fun deriveHdNode(hdNodeJNI: HDNodeJNI, path: String): HDNodeJNI

    external fun signMessage(hdNodeJNI: HDNodeJNI, message: ByteArray): ByteArray
}