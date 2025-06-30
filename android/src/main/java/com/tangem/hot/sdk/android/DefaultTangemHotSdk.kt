package com.tangem.hot.sdk.android

import androidx.fragment.app.FragmentActivity
import com.tangem.TangemSdk
import com.tangem.common.authentication.keystore.KeystoreManager
import com.tangem.common.card.EllipticCurve
import com.tangem.common.services.secure.SecureStorage
import com.tangem.crypto.Bls
import com.tangem.crypto.bip39.Mnemonic
import com.tangem.crypto.hdWallet.DerivationPath
import com.tangem.crypto.sign
import com.tangem.hot.sdk.TangemHotSdk
import com.tangem.hot.sdk.android.model.PrivateInfo
import com.tangem.hot.sdk.model.DataToSign
import com.tangem.hot.sdk.model.DeriveWalletRequest
import com.tangem.hot.sdk.model.DerivedPublicKeyResponse
import com.tangem.hot.sdk.model.HotAuth
import com.tangem.hot.sdk.model.HotWalletId
import com.tangem.hot.sdk.model.MnemonicType
import com.tangem.hot.sdk.model.SeedPhrasePrivateInfo
import com.tangem.hot.sdk.model.SignedData
import com.tangem.hot.sdk.model.UnlockHotWallet
import com.tangem.sdk.extensions.initAuthenticationManager
import com.tangem.sdk.extensions.initKeystoreManager
import com.tangem.sdk.storage.AndroidSecureStorageV2
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import wallet.core.jni.Curve
import wallet.core.jni.HDWallet
import java.util.UUID

internal class DefaultTangemHotSdk(
    private val mnemonicRepository: MnemonicRepository,
    private val secureStorage: SecureStorage,
    private val keystoreManager: KeystoreManager,
) : TangemHotSdk {

    private val privateInfoStorage = PrivateInfoStorage(
        secureStorage = secureStorage,
        keystoreManager = keystoreManager,
    )

    override suspend fun importWallet(mnemonic: Mnemonic, passphrase: CharArray?, auth: HotAuth): HotWalletId =
        withContext(Dispatchers.IO) {
            generateWalletId(
                authType = when (auth) {
                    is HotAuth.Password -> HotWalletId.AuthType.Password
                    is HotAuth.NoAuth -> HotWalletId.AuthType.NoPassword
                    is HotAuth.Biometry -> HotWalletId.AuthType.Biometry
                },
            ).also {
                privateInfoStorage.store(
                    UnlockHotWallet(auth = auth, walletId = it),
                    privateInfo = PrivateInfo(
                        entropy = mnemonic.getEntropy(),
                        passphrase = passphrase,
                    ),
                )
            }
        }

    override suspend fun generateWallet(auth: HotAuth, mnemonicType: MnemonicType): HotWalletId {
        return importWallet(
            mnemonic = mnemonicRepository.generateMnemonic(),
            passphrase = null,
            auth = auth,
        )
    }

    override suspend fun exportMnemonic(unlockHotWallet: UnlockHotWallet): SeedPhrasePrivateInfo =
        withContext(Dispatchers.IO) {
            privateInfoStorage.getContainer(unlockHotWallet).use { privateInfo ->
                SeedPhrasePrivateInfo(
                    mnemonic = mnemonicRepository.generateMnemonic(entropy = privateInfo.entropy),
                    passphrase = privateInfo.passphrase,
                )
            }
        }

    override suspend fun exportBackup(unlockHotWallet: UnlockHotWallet): ByteArray {
        return ByteArray(0) // Placeholder for backup export logic
    }

    override suspend fun derivePublicKey(
        unlockHotWallet: UnlockHotWallet,
        request: DeriveWalletRequest,
    ): DerivedPublicKeyResponse = withContext(Dispatchers.IO) {
        privateInfoStorage.getContainer(unlockHotWallet).use { privateInfo ->
            val hdWallet = HDWallet(
                privateInfo.entropy,
                privateInfo.passphrase?.let { String(it) } ?: "",
            )

            val entries = request.requests.map {
                DerivedPublicKeyResponse.ResponseEntry(
                    curve = it.curve,
                    publicKeys = it.paths.associate { path ->
                        val derivedKey = deriveKey(hdWallet, it.curve, path)
                        path to derivedKey
                    },
                )
            }

            DerivedPublicKeyResponse(responses = entries)
        }
    }

    override suspend fun delete(id: HotWalletId) = withContext(Dispatchers.IO) {
        privateInfoStorage.delete(id)
    }

    override suspend fun changeAuth(unlockHotWallet: UnlockHotWallet, auth: HotAuth) = withContext(Dispatchers.IO) {
        privateInfoStorage.changeStore(unlockHotWallet, auth)
    }

    override suspend fun signHashes(unlockHotWallet: UnlockHotWallet, dataToSign: List<DataToSign>): List<SignedData> =
        withContext(Dispatchers.IO) {
            privateInfoStorage.getContainer(unlockHotWallet).use { privateInfo ->
                val hdWallet = HDWallet(
                    privateInfo.entropy,
                    privateInfo.passphrase?.let { String(it) } ?: "",
                )

                dataToSign.map {
                    val derivedKey = deriveKey(hdWallet, it.curve, it.derivationPath)

                    SignedData(
                        curve = it.curve,
                        derivationPath = it.derivationPath,
                        signatures = it.hashes.map { hash ->
                            hash.sign(
                                privateKeyArray = derivedKey,
                                curve = it.curve,
                            )
                        },
                    )
                }
            }
        }

    private fun deriveKey(hdWallet: HDWallet, curve: EllipticCurve, derivationPath: DerivationPath?): ByteArray {
        if (setOf(
                EllipticCurve.Bls12381G2,
                EllipticCurve.Bls12381G2Aug,
                EllipticCurve.Bls12381G2Pop,
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

    private fun generateWalletId(authType: HotWalletId.AuthType): HotWalletId {
        return HotWalletId(
            value = UUID.randomUUID().toString(),
            authType = authType,
        )
    }
}

fun TangemHotSdk.Companion.create(activity: FragmentActivity): TangemHotSdk {
    val appContext = activity.applicationContext
    val authenticationManager = TangemSdk.initAuthenticationManager(activity)
    val secureStorage = AndroidSecureStorageV2(
        appContext = appContext,
        name = "tangem_hot_sdk_secure_storage",
    )
    val keystoreManager = TangemSdk.initKeystoreManager(authenticationManager, secureStorage)

    return DefaultTangemHotSdk(
        mnemonicRepository = MnemonicRepository(appContext),
        secureStorage = secureStorage,
        keystoreManager = keystoreManager,
    )
}