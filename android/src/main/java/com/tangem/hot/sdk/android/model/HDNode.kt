package com.tangem.hot.sdk.android.model

import com.tangem.common.card.EllipticCurve
import com.tangem.crypto.hdWallet.bip32.ExtendedPublicKey
import com.tangem.hot.sdk.android.jni.HDNodeJNI

internal class HDNode(
    val publicKey: ExtendedPublicKey,
    val curve: EllipticCurve,
    val hdNodeJNI: HDNodeJNI? = null, // Optional, used for signing
    val blsPrivateKey: ByteArray? = null, // Optional, used for BLS curves
) {
    var destroyed: Boolean = false
        private set

    fun destroy() {
        if (destroyed) return

        hdNodeJNI?.destroyNative()
        blsPrivateKey?.fill(0)
        destroyed = true
    }
}