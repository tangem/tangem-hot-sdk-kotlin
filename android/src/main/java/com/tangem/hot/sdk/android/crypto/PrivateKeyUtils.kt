package com.tangem.hot.sdk.android.crypto

import com.tangem.common.CompletionResult
import com.tangem.common.card.EllipticCurve
import com.tangem.crypto.Bls
import com.tangem.crypto.hdWallet.DerivationPath
import com.tangem.crypto.hdWallet.bip32.ExtendedPublicKey
import com.tangem.hot.sdk.android.MnemonicRepository
import com.tangem.hot.sdk.android.model.HDNode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal class PrivateKeyUtils(
    private val mnemonicRepository: MnemonicRepository,
) {

    suspend fun sign(data: ByteArray, hdNode: HDNode) = withContext(Dispatchers.Default) {
        val curve = hdNode.curve

        when (curve) {
            EllipticCurve.Secp256k1,
            EllipticCurve.Ed25519, EllipticCurve.Ed25519Slip0010,
            -> {
                if (hdNode.hdNodeJNI == null) {
                    error("HDNodeJNI is null for curve: ${curve.curve}")
                }
                TrezorCryptoFacade.signMessage(hdNode.hdNodeJNI, data)
            }

            EllipticCurve.Bls12381G2,
            EllipticCurve.Bls12381G2Aug,
            EllipticCurve.Bls12381G2Pop,
            -> {
                if (hdNode.blsPrivateKey == null) {
                    error("BLS private key is null for curve: ${curve.curve}")
                }
                Bls.signHash(data, hdNode.blsPrivateKey)
            }

            else -> error("Unsupported curve: ${curve.curve}")
        }
    }

    suspend fun deriveKey(
        entropy: ByteArray,
        passphrase: CharArray?,
        curve: EllipticCurve,
        derivationPath: DerivationPath?,
    ): HDNode = withContext(Dispatchers.Default) {
        if (curve in setOf(
                EllipticCurve.Bls12381G2,
                EllipticCurve.Bls12381G2Aug,
                EllipticCurve.Bls12381G2Pop,
            )
        ) {
            return@withContext deriveBls(
                entropy = entropy,
                passphrase = passphrase,
                curve = curve,
            )
        }

        val masterNode = TrezorCryptoFacade.masterHdNode(
            entropy = entropy,
            passphrase = passphrase,
            curve = curve,
        )

        if (derivationPath != null) {
            TrezorCryptoFacade.deriveHdNode(
                hdNode = masterNode,
                derivationPath = derivationPath,
            )
        } else {
            masterNode
        }
    }

    private suspend fun deriveBls(entropy: ByteArray, passphrase: CharArray?, curve: EllipticCurve): HDNode =
        withContext(Dispatchers.Default) {
            val seedResult = mnemonicRepository.generateMnemonic(entropy)
                .generateSeed(
                    passphrase?.let { String(it) } ?: "",
                ) as? CompletionResult.Success<ByteArray>
                ?: error("Failed to generate seed from mnemonic")

            val seed = seedResult.data
            val masterKey = Bls.makeMasterKey(seed)
            val publicKey = ExtendedPublicKey(
                publicKey = Bls.generatePublicKey(masterKey),
                chainCode = ByteArray(0),
            )

            HDNode(
                publicKey = publicKey,
                curve = curve,
                blsPrivateKey = masterKey,
            )
        }
}