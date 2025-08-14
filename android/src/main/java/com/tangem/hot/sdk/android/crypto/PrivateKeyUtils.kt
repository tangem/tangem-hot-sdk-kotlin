package com.tangem.hot.sdk.android.crypto

import com.tangem.common.CompletionResult
import com.tangem.common.card.EllipticCurve
import com.tangem.crypto.Bls
import com.tangem.crypto.Ed25519
import com.tangem.crypto.Secp256k1
import com.tangem.crypto.hdWallet.DerivationPath
import com.tangem.crypto.hdWallet.bip32.ExtendedPrivateKey
import com.tangem.crypto.hdWallet.bip32.ExtendedPublicKey
import com.tangem.crypto.sign
import com.tangem.hot.sdk.android.MnemonicRepository
import com.tangem.hot.sdk.android.model.DerivedKeyPair
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal class PrivateKeyUtils(
    private val mnemonicRepository: MnemonicRepository,
) {

    suspend fun sign(data: ByteArray, derivedKeyPair: DerivedKeyPair) = withContext(Dispatchers.Default) {
        val privateKey = derivedKeyPair.privateKey.privateKey
        val curve = derivedKeyPair.curve

        when (curve) {
            EllipticCurve.Secp256k1,
            EllipticCurve.Ed25519, EllipticCurve.Ed25519Slip0010,
            ->
                TrezorCryptoFacade.signMessage(derivedKeyPair.hdNodeJNI!!, data)

            EllipticCurve.Bls12381G2,
            EllipticCurve.Bls12381G2Aug,
            EllipticCurve.Bls12381G2Pop,
            -> Bls.signHash(data, privateKey)

            else -> data.sign(privateKey, curve)
        }
    }

    suspend fun deriveKey(
        entropy: ByteArray,
        passphrase: CharArray?,
        curve: EllipticCurve,
        derivationPath: DerivationPath?,
    ): DerivedKeyPair = withContext(Dispatchers.Default) {
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
                derivedKeyPair = masterNode,
                derivationPath = derivationPath,
            )
        } else {
            masterNode
        }
    }

    private suspend fun deriveBls(entropy: ByteArray, passphrase: CharArray?, curve: EllipticCurve): DerivedKeyPair =
        withContext(Dispatchers.Default) {
            val seedResult = mnemonicRepository.generateMnemonic(entropy)
                .generateSeed(
                    passphrase?.let { String(it) } ?: "",
                ) as? CompletionResult.Success<ByteArray>
                ?: error("Failed to generate seed from mnemonic")
            val seed = seedResult.data
            val privateKey = ExtendedPrivateKey(
                privateKey = Bls.makeMasterKey(seed),
                chainCode = ByteArray(0),
            )
            val publicKey = ExtendedPublicKey(
                Bls.generatePublicKey(seed),
                chainCode = ByteArray(0),
            )
            return@withContext DerivedKeyPair(
                privateKey = privateKey,
                publicKey = publicKey,
                curve = curve,
            )
        }
}