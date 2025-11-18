package com.tangem.hot.sdk.android

import com.tangem.common.authentication.keystore.KeystoreManager
import com.tangem.common.authentication.storage.AuthenticatedStorage
import com.tangem.common.services.secure.SecureStorage
import com.tangem.hot.sdk.android.crypto.AESEncryptionProtocol
import com.tangem.hot.sdk.model.HotAuth
import com.tangem.hot.sdk.model.HotWalletId
import com.tangem.hot.sdk.android.model.PrivateInfo
import com.tangem.hot.sdk.android.model.PrivateInfoContainer
import com.tangem.hot.sdk.exception.NoContextualAuthAvailable
import com.tangem.hot.sdk.exception.WrongPasswordException
import com.tangem.hot.sdk.model.UnlockHotWallet
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

private const val PRIVATE_INFO_PREFIX = "hotsdk_private_info_"
private const val ENCRYPTION_KEY_PREFIX = "hotsdk_encryption_key_"
private const val AUTH_ENCRYPTION_KEY_PREFIX = "hotsdk_auth_encryption_key_"
private const val AES_KEY_SIZE = 32

internal class PrivateInfoStorage(
    private val secureStorage: SecureStorage,
    private val keystoreManager: KeystoreManager,
) {
    private val authenticatedStorage = AuthenticatedStorage(
        secureStorage = secureStorage,
        keystoreManager = keystoreManager,
    )

    private val contextualAESKeysStorage = ConcurrentHashMap<HotWalletId, ByteArray>()

    suspend fun createContext(unlockHotWallet: UnlockHotWallet) {
        val aesKey = getAesKeyByUnlock(unlockHotWallet)
        contextualAESKeysStorage[unlockHotWallet.walletId] = aesKey
    }

    fun clearContext(walletId: HotWalletId) {
        contextualAESKeysStorage.remove(walletId)?.fill(0)
    }

    suspend fun store(unlockHotWallet: UnlockHotWallet, privateInfo: PrivateInfo) {
        val aesKey = generateAESEncryptionKey()
        try {
            val encrypted =
                AESEncryptionProtocol.encryptAES(aesKey, privateInfo.toByteArray(), null)

            when (val auth = unlockHotWallet.auth) {
                HotAuth.NoAuth -> {
                    secureStorage.store(
                        data = aesKey,
                        account = unlockHotWallet.walletId.storageEncryptionKey(),
                    )
                }

                is HotAuth.Password -> {
                    val aesKeyEncrypted = AESEncryptionProtocol.encryptWithPassword(
                        password = auth.value,
                        content = aesKey,
                    )
                    secureStorage.store(
                        data = aesKeyEncrypted,
                        account = unlockHotWallet.walletId.storageEncryptionKey(),
                    )
                }

                HotAuth.Biometry -> {
                    authenticatedStorage.store(
                        keyAlias = unlockHotWallet.walletId.authStorageEncryptionKey(),
                        data = aesKey,
                    )
                }

                HotAuth.Contextual -> {
                    error("Contextual auth is not supported for storing private info")
                }
            }

            secureStorage.store(
                data = encrypted,
                account = unlockHotWallet.walletId.storageKey(),
            )
        } finally {
            aesKey.fill(0)
        }
    }

    suspend fun changeStore(unlockHotWallet: UnlockHotWallet, newHotAuth: HotAuth) {
        if (unlockHotWallet.auth == newHotAuth) {
            return
        }

        val aesKey = getAesKeyByUnlock(unlockHotWallet)

        try {
            require(aesKey.size == AES_KEY_SIZE) {
                "Unexpected AES key size: ${aesKey.size}, expected $AES_KEY_SIZE bytes"
            }

            when (newHotAuth) {
                HotAuth.NoAuth -> {
                    secureStorage.store(
                        data = aesKey,
                        account = unlockHotWallet.walletId.storageEncryptionKey(),
                    )
                }

                is HotAuth.Password -> {
                    val aesEncrypted = AESEncryptionProtocol.encryptWithPassword(
                        password = newHotAuth.value,
                        content = aesKey,
                    )
                    secureStorage.store(
                        data = aesEncrypted,
                        account = unlockHotWallet.walletId.storageEncryptionKey(),
                    )
                }

                HotAuth.Biometry -> {
                    if (unlockHotWallet.auth == HotAuth.NoAuth) {
                        secureStorage.delete(unlockHotWallet.walletId.storageEncryptionKey())
                    }

                    authenticatedStorage.store(
                        keyAlias = unlockHotWallet.walletId.authStorageEncryptionKey(),
                        data = aesKey,
                    )
                }

                HotAuth.Contextual -> {
                    error("Contextual auth is not supported for storing private info")
                }
            }
        } finally {
            aesKey.fill(0)
        }
    }

    fun removeBiometryAuth(hotWalletId: HotWalletId): HotWalletId {
        authenticatedStorage.delete(hotWalletId.authStorageEncryptionKey())
        return hotWalletId.copy(
            authType = when (hotWalletId.authType) {
                HotWalletId.AuthType.Biometry -> HotWalletId.AuthType.Password
                else -> hotWalletId.authType
            },
        )
    }

    fun delete(hotWalletId: HotWalletId) {
        secureStorage.delete(hotWalletId.storageKey())
        secureStorage.delete(hotWalletId.storageEncryptionKey())
        authenticatedStorage.delete(hotWalletId.authStorageEncryptionKey())
    }

    fun getContainer(unlockHotWallet: UnlockHotWallet): PrivateInfoContainer {
        return PrivateInfoContainer(
            getPrivateInfo = {
                val encryptedData =
                    secureStorage.get(unlockHotWallet.walletId.storageKey())
                        ?: error("No private info found for wallet ${unlockHotWallet.walletId}")

                val aesKey = getAesKeyByUnlock(unlockHotWallet)

                try {
                    AESEncryptionProtocol.decryptAES(
                        rawEncryptionKey = aesKey,
                        encryptedData = encryptedData,
                        associatedData = null,
                    )!!
                } finally {
                    if (unlockHotWallet.auth !is HotAuth.Contextual) {
                        aesKey.fill(0)
                    }
                }
            },
        )
    }

    private suspend fun getAesKeyByUnlock(unlockHotWallet: UnlockHotWallet): ByteArray {
        return when (val auth = unlockHotWallet.auth) {
            HotAuth.NoAuth -> {
                secureStorage.get(unlockHotWallet.walletId.storageEncryptionKey())
                    ?: error("No encryption key found for wallet ${unlockHotWallet.walletId}")
            }

            is HotAuth.Password -> {
                val aesKeyEncrypted =
                    secureStorage.get(unlockHotWallet.walletId.storageEncryptionKey())
                        ?: error("No encryption key found for wallet ${unlockHotWallet.walletId}")

                AESEncryptionProtocol.decryptWithPassword(
                    password = auth.value,
                    encryptedData = aesKeyEncrypted,
                ) ?: throw WrongPasswordException()
            }

            HotAuth.Biometry -> {
                authenticatedStorage.get(unlockHotWallet.walletId.authStorageEncryptionKey())
                    ?: error("No private info found for wallet ${unlockHotWallet.walletId}")
            }

            HotAuth.Contextual -> {
                contextualAESKeysStorage[unlockHotWallet.walletId]
                    ?: throw NoContextualAuthAvailable()
            }
        }
    }

    private fun generateAESEncryptionKey(): ByteArray {
        val key = ByteArray(AES_KEY_SIZE)
        SecureRandom().nextBytes(key)
        return key
    }

    private fun HotWalletId.storageKey(): String {
        return PRIVATE_INFO_PREFIX + value
    }

    private fun HotWalletId.storageEncryptionKey(): String {
        return ENCRYPTION_KEY_PREFIX + value
    }

    private fun HotWalletId.authStorageEncryptionKey(): String {
        return AUTH_ENCRYPTION_KEY_PREFIX + value
    }
}