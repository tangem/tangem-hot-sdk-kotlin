package com.tangem.hot.sdk.android.crypto

import com.tangem.blstlib.generated.P1
import com.tangem.blstlib.generated.P2
import com.tangem.blstlib.generated.Scalar
import com.tangem.blstlib.generated.SecretKey
import com.tangem.common.CompletionResult
import com.tangem.common.card.EllipticCurve
import com.tangem.common.core.TangemSdkError
import com.tangem.crypto.hdWallet.DerivationPath
import com.tangem.crypto.hdWallet.bip32.ExtendedPublicKey
import com.tangem.hot.sdk.android.MnemonicRepository
import com.tangem.hot.sdk.android.model.HDNode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal class PrivateKeyUtils(
    private val mnemonicRepository: MnemonicRepository,
) {

    suspend fun sign(data: ByteArray, hdNode: HDNode): ByteArray = withContext(Dispatchers.Default) {
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
                signBlsWithBlstlib(data, hdNode.blsPrivateKey)
            }

            else -> error("Unsupported curve: ${curve.curve}")
        }
    }

    private fun signBlsWithBlstlib(data: ByteArray, privateKey: ByteArray): ByteArray {
        require(data.size == BLS_G2_POINT_SIZE) {
            "Invalid G2 point size: expected $BLS_G2_POINT_SIZE bytes, got ${data.size} bytes"
        }
        require(privateKey.isNotEmpty() && privateKey.size <= BLS_PRIVATE_KEY_SIZE) {
            "Invalid private key size: expected 1-$BLS_PRIVATE_KEY_SIZE bytes, got ${privateKey.size} bytes"
        }

        return try {
            val g2Point = P2(data)
            val scalar = Scalar().from_bendian(privateKey.padTo32Bytes())
            val signature = g2Point.mult(scalar)
            signature.compress()
        } catch (e: Exception) {
            throw IllegalStateException("BLS signing failed: ${e.message.orEmpty()}", e)
        }
    }

    private fun ByteArray.padTo32Bytes(): ByteArray {
        return when {
            this.size < BLS_PRIVATE_KEY_SIZE -> ByteArray(BLS_PRIVATE_KEY_SIZE - this.size) + this
            this.size == BLS_PRIVATE_KEY_SIZE -> this
            else -> error("Private key size exceeds $BLS_PRIVATE_KEY_SIZE bytes")
        }
    }

    suspend fun deriveKey(
        entropy: ByteArray,
        passphrase: CharArray?,
        curve: EllipticCurve,
        derivationPath: DerivationPath?,
    ): HDNode = withContext(Dispatchers.Default) {
        checkForDerivationSupport(curve, derivationPath)

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

    private fun checkForDerivationSupport(curve: EllipticCurve, derivationPath: DerivationPath?) {
        val hasNotHardenedNodes = derivationPath != null && derivationPath.nodes.any { node -> !node.isHardened }
        if (curve == EllipticCurve.Ed25519Slip0010 && hasNotHardenedNodes) {
            throw TangemSdkError.NonHardenedDerivationNotSupported()
        }
    }

    private suspend fun deriveBls(entropy: ByteArray, passphrase: CharArray?, curve: EllipticCurve): HDNode =
        withContext(Dispatchers.Default) {
            val seedResult = mnemonicRepository.generateMnemonic(entropy)
                .generateSeed(
                    passphrase?.let { String(it) }.orEmpty(),
                ) as? CompletionResult.Success<ByteArray>
                ?: error("Failed to generate seed from mnemonic")

            val seed = seedResult.data
            val secretKey = SecretKey()
            secretKey.derive_master_eip2333(seed)
            val publicKeyG1 = P1(secretKey)
            val publicKeyBytes = publicKeyG1.compress()

            val publicKey = ExtendedPublicKey(
                publicKey = publicKeyBytes,
                chainCode = ByteArray(0),
            )

            HDNode(
                publicKey = publicKey,
                curve = curve,
                blsPrivateKey = secretKey.to_bendian(),
            )
        }

    private companion object {
        private const val BLS_PRIVATE_KEY_SIZE = 32
        private const val BLS_G2_POINT_SIZE = 96
    }
}