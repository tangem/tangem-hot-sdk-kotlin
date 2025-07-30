package com.tangem.hot.sdk.android.crypto

import com.tangem.common.card.EllipticCurve
import com.tangem.crypto.Bls
import com.tangem.crypto.Secp256k1
import com.tangem.crypto.hdWallet.DerivationPath
import com.tangem.crypto.hdWallet.bip32.ExtendedPrivateKey
import com.tangem.crypto.sign
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal object PrivateKeyUtils {

    suspend fun sign(data: ByteArray, privateKey: ByteArray, curve: EllipticCurve): ByteArray =
        withContext(Dispatchers.Default) {
            when (curve) {
                EllipticCurve.Secp256k1 -> Secp256k1.ecdsaSignDigest(data, privateKey)
                else -> data.sign(privateKey, curve)
            }
        }

    suspend fun deriveKey(seed: ByteArray, curve: EllipticCurve, derivationPath: DerivationPath?): ExtendedPrivateKey =
        withContext(Dispatchers.Default) {
            if (setOf(
                    EllipticCurve.Bls12381G2,
                    EllipticCurve.Bls12381G2Aug,
                    EllipticCurve.Bls12381G2Pop,
                ).contains(curve)
            ) {
                return@withContext ExtendedPrivateKey(
                    privateKey = Bls.makeMasterKey(seed),
                    chainCode = ByteArray(0),
                )
            }

            TrezorCryptoFacade.deriveKey(
                seed = seed,
                curve = curve,
                derivationPath = derivationPath,
            )
        }
}