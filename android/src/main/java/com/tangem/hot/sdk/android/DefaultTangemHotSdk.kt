package com.tangem.hot.sdk.android

import androidx.fragment.app.FragmentActivity
import com.tangem.TangemSdk
import com.tangem.common.authentication.keystore.KeystoreManager
import com.tangem.common.services.secure.SecureStorage
import com.tangem.crypto.CryptoUtils
import com.tangem.crypto.bip39.Mnemonic
import com.tangem.hot.sdk.TangemHotSdk
import com.tangem.hot.sdk.android.crypto.EntropyUtils.adjustTo16And32Bytes
import com.tangem.hot.sdk.android.crypto.PrivateKeyUtils
import com.tangem.hot.sdk.android.model.HDNode
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
import java.util.UUID

internal class DefaultTangemHotSdk(
    private val mnemonicRepository: MnemonicRepository,
    private val secureStorage: SecureStorage,
    private val keystoreManager: KeystoreManager,
) : TangemHotSdk {

    init {
        CryptoUtils.initCrypto()
    }

    private val privateKeyUtils = PrivateKeyUtils(mnemonicRepository)

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
                    HotAuth.Contextual -> error("Contextual auth is not supported for wallet creation")
                },
            ).also {
                val privateInfo = PrivateInfo(
                    entropy = mnemonic.getEntropy().adjustTo16And32Bytes(),
                    passphrase = passphrase,
                )

                privateInfoStorage.store(
                    UnlockHotWallet(auth = auth, walletId = it),
                    privateInfo = privateInfo,
                )

                privateInfo.clear()
            }
        }

    override suspend fun generateWallet(auth: HotAuth, mnemonicType: MnemonicType): HotWalletId {
        return importWallet(
            mnemonic = mnemonicRepository.generateMnemonic(mnemonicType),
            passphrase = null,
            auth = auth,
        )
    }

    override suspend fun exportMnemonic(unlockHotWallet: UnlockHotWallet): SeedPhrasePrivateInfo =
        withContext(Dispatchers.IO) {
            privateInfoStorage.getContainer(unlockHotWallet).use { privateInfo ->
                SeedPhrasePrivateInfo(
                    mnemonic = mnemonicRepository.generateMnemonic(entropy = privateInfo.entropy),
                    passphrase = privateInfo.passphrase?.copyOf(),
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
            val entries = request.requests.map {
                val createdHdNodes = mutableListOf<HDNode>()

                try {
                    val masterHdNode = privateKeyUtils.deriveKey(
                        entropy = privateInfo.entropy,
                        passphrase = privateInfo.passphrase,
                        curve = it.curve,
                        derivationPath = null,
                    ).also {
                        createdHdNodes.add(it)
                    }

                    val derivedHdNodes = it.paths.associate { path ->
                        path to privateKeyUtils.deriveKey(
                            entropy = privateInfo.entropy,
                            passphrase = privateInfo.passphrase,
                            curve = it.curve,
                            derivationPath = path,
                        ).also {
                            createdHdNodes.add(it)
                        }
                    }

                    DerivedPublicKeyResponse.ResponseEntry(
                        curve = it.curve,
                        seedKey = masterHdNode.publicKey,
                        publicKeys = derivedHdNodes.mapValues { it.value.publicKey },
                    )
                } finally {
                    createdHdNodes.forEach { hdNode ->
                        hdNode.destroy()
                    }
                }
            }

            DerivedPublicKeyResponse(responses = entries)
        }
    }

    override suspend fun delete(id: HotWalletId) = withContext(Dispatchers.IO) {
        privateInfoStorage.delete(id)
    }

    override suspend fun changeAuth(unlockHotWallet: UnlockHotWallet, auth: HotAuth) = withContext(Dispatchers.IO) {
        privateInfoStorage.changeStore(unlockHotWallet, auth)
        unlockHotWallet.walletId.copy(
            authType = when (auth) {
                is HotAuth.Password -> HotWalletId.AuthType.Password
                is HotAuth.NoAuth -> HotWalletId.AuthType.NoPassword
                is HotAuth.Biometry -> HotWalletId.AuthType.Biometry
                else -> error("Contextual auth is not supported for changing auth type")
            },
        )
    }

    override suspend fun getContextUnlock(unlockHotWallet: UnlockHotWallet): UnlockHotWallet =
        withContext(Dispatchers.IO) {
            privateInfoStorage.createContext(unlockHotWallet)
            unlockHotWallet.copy(auth = HotAuth.Contextual)
        }

    override suspend fun clearUnlockContext(hotWalletId: HotWalletId) {
        privateInfoStorage.clearContext(hotWalletId)
    }

    override suspend fun removeBiometryAuthIfPresented(id: HotWalletId): HotWalletId = withContext(Dispatchers.IO) {
        privateInfoStorage.removeBiometryAuth(id)
    }

    override suspend fun signHashes(unlockHotWallet: UnlockHotWallet, dataToSign: List<DataToSign>): List<SignedData> =
        withContext(Dispatchers.IO) {
            privateInfoStorage.getContainer(unlockHotWallet).use { privateInfo ->
                dataToSign.map {
                    var hdNode: HDNode? = null
                    try {
                        hdNode = privateKeyUtils.deriveKey(
                            entropy = privateInfo.entropy,
                            passphrase = privateInfo.passphrase,
                            curve = it.curve,
                            derivationPath = it.derivationPath,
                        )

                        SignedData(
                            curve = it.curve,
                            derivationPath = it.derivationPath,
                            signatures = it.hashes.map { hash ->
                                privateKeyUtils.sign(
                                    data = hash,
                                    hdNode = hdNode,
                                )
                            },
                        )
                    } finally {
                        hdNode?.destroy()
                    }
                }
            }
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
        useStrongBox = true,
        name = "tangem_hot_sdk_secure_storage",
    )
    val keystoreManager = TangemSdk.initKeystoreManager(authenticationManager, secureStorage)

    return DefaultTangemHotSdk(
        mnemonicRepository = MnemonicRepository(appContext),
        secureStorage = secureStorage,
        keystoreManager = keystoreManager,
    )
}