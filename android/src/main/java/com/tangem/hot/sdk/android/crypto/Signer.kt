package com.tangem.hot.sdk.android.crypto

import com.tangem.common.card.EllipticCurve
import com.tangem.crypto.Secp256k1
import com.tangem.crypto.sign

internal object Signer {

    fun sign(data: ByteArray, privateKey: ByteArray, curve: EllipticCurve): ByteArray {
        return when (curve) {
            EllipticCurve.Secp256k1 -> Secp256k1.ecdsaSignDigest(data, privateKey)
            else -> data.sign(privateKey, curve)
        }
    }
}