package com.tangem.hot.sdk

import com.tangem.common.authentication.keystore.KeystoreManager
import com.tangem.common.card.EllipticCurve
import com.tangem.crypto.Bls
import com.tangem.crypto.bip39.Mnemonic
import com.tangem.crypto.hdWallet.DerivationPath
import com.tangem.crypto.sign
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import wallet.core.jni.Curve
import wallet.core.jni.HDWallet
import java.util.UUID

class DefaultTangemHotSdk(
    private val mnemonicRepository: MnemonicRepository,
    private val keystoreManager: KeystoreManager,
) : TangemHotSdk {

    override suspend fun importMnemonic(
        mnemonic: Mnemonic,
        passphrase: CharArray?,
        auth: HotAuth.Password
    ): HotWalletId {
        val id = generateWalletId()
        TODO()
    }

    override suspend fun generateWallet(
        auth: HotAuth.Password,
        mnemonicType: MnemonicRepository.MnemonicType
    ): HotWalletId {
        return importMnemonic(
            mnemonic = mnemonicRepository.generateMnemonic(),
            passphrase = null,
            auth = auth
        )
    }

    override fun showMnemonic(id: HotWalletId) {
        TODO("Not yet implemented")
    }

    override fun exportMnemonic(
        id: HotWalletId,
        auth: HotAuth,
        exportFile: (ByteArray) -> Unit
    ) {
        TODO("Not yet implemented")
    }

    override fun getExistingWallets(): List<HotWalletId> {
        TODO("Not yet implemented")
    }

    override suspend fun getInfo(
        id: HotWalletId,
        auth: HotAuth
    ): HotWalletInfo {
        TODO("Not yet implemented")
    }

    override fun remove(id: HotWalletId) {
        TODO("Not yet implemented")
    }

    override suspend fun signHashes(
        id: HotWalletId,
        auth: HotAuth,
        curve: EllipticCurve,
        derivationPath: DerivationPath?,
        hashes: List<ByteArray>
    ): List<ByteArray> = withContext(Dispatchers.IO) {
        val privateInfo = PrivateInfoContainer(
            getPrivateInfo = {
                val entropy = ByteArray(0) //TODO
                val passphrase = CharArray(0) //TODO
                entropy //TODO
            }
        )

        privateInfo.use { info ->
            val entropy = info //TODO
            val passphrase = CharArray(0) //TODO

            val hdWallet = HDWallet(entropy, passphrase.toString())
            val derivedKey = deriveKey(hdWallet, curve, derivationPath)

            hashes.map {
                it.sign(
                    privateKeyArray = derivedKey,
                    curve = curve
                )
            }
        }
    }

    override suspend fun multiSign(
        id: HotWalletId,
        auth: HotAuth,
        curve: EllipticCurve,
        derivationPath: DerivationPath?,
        hashes: List<ByteArray>
    ): Map<ByteArray, ByteArray> {
        TODO("Not yet implemented")
    }

    private fun deriveKey(
        hdWallet: HDWallet,
        curve: EllipticCurve,
        derivationPath: DerivationPath?
    ) : ByteArray {
        if (setOf(
                EllipticCurve.Bls12381G2,
                EllipticCurve.Bls12381G2Aug,
                EllipticCurve.Bls12381G2Pop
            ).contains(curve)
        ) {
            return Bls.makeMasterKey(hdWallet.seed())
        }

        val wcCurve = when (curve) {
            EllipticCurve.Secp256k1 -> Curve.SECP256K1
            EllipticCurve.Ed25519 -> Curve.ED25519EXTENDEDCARDANO
            EllipticCurve.Ed25519Slip0010 -> Curve.ED25519
            else -> error("Unsupported curve: $curve")
        }

        return hdWallet.getKeyByCurve(wcCurve, derivationPath?.rawPath ?: "").data()
    }


    private fun generateWalletId(): HotWalletId {
        return HotWalletId(UUID.randomUUID().toString())
    }
}