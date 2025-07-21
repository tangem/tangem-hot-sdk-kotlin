package com.tangem.hot.sdk.android.crypto

import com.tangem.common.card.EllipticCurve
import com.tangem.common.extensions.hexToBytes
import com.tangem.crypto.hdWallet.DerivationPath
import com.tangem.crypto.hdWallet.bip32.ExtendedPrivateKey
import com.tangem.hot.sdk.android.jni.TrezorCryptoJNI
import com.tangem.hot.sdk.android.jni.toTrezorCurveName

internal object TrezorCryptoFacade {

    fun deriveKey(seed: ByteArray, curve: EllipticCurve, derivationPath: DerivationPath?): ExtendedPrivateKey {
        val hdNode = TrezorCryptoJNI.derive(
            seed = seed,
            path = derivationPath?.rawPath,
            curveName = curve.toTrezorCurveName(),
        )

        return ExtendedPrivateKey(
            privateKey = hdNode.privateKey,
            chainCode = hdNode.chainCode,
            depth = hdNode.depth,
            parentFingerprint = if (derivationPath == null) {
                "0x00000000".hexToBytes()
            } else {
                hdNode.fingerprint()
            },
            childNumber = derivationPath?.nodes?.lastIndex?.toLong() ?: 0,
        )
    }
}