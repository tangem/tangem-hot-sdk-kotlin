package com.tangem.hot.sdk.android

import com.tangem.common.authentication.keystore.KeystoreManager
import com.tangem.common.authentication.storage.AuthenticatedStorage
import com.tangem.common.services.secure.SecureStorage
import com.tangem.hot.sdk.android.crypto.AESEncryptionProtocol
import com.tangem.hot.sdk.model.HotAuth
import com.tangem.hot.sdk.model.HotWalletId
import com.tangem.hot.sdk.android.model.PrivateInfo
import com.tangem.hot.sdk.android.model.PrivateInfoContainer
import com.tangem.hot.sdk.exception.WrongPasswordException
import com.tangem.hot.sdk.model.UnlockHotWallet
import java.security.SecureRandom

private const val PRIVATE_INFO_PREFIX = "hotsdk_private_info_"
private const val ENCRYPTION_KEY_PREFIX = "hotsdk_encryption_key_"
private const val AES_KEY_SIZE = 32

internal class PrivateInfoStorage(
    private val secureStorage: SecureStorage,
    private val keystoreManager: KeystoreManager,
) {
    private val authenticatedStorage = AuthenticatedStorage(
        secureStorage = secureStorage,
        keystoreManager = keystoreManager,
    )

    suspend fun store(unlockHotWallet: UnlockHotWallet, privateInfo: PrivateInfo) {
        val aesKey = generateAESEncryptionKey()
        try {
            val encrypted =
                AESEncryptionProtocol.encryptAES(aesKey, privateInfo.toByteArray(), null)

            when (val auth = unlockHotWallet.auth) {
                HotAuth.NoAuth -> {
                    secureStorage.store(
                        data = aesKey,
                        account = unlockHotWallet.storageEncryptionKey(),
                    )
                }

                is HotAuth.Password -> {
                    val aesKeyEncrypted = AESEncryptionProtocol.encryptWithPassword(
                        password = auth.value,
                        content = aesKey,
                    )
                    secureStorage.store(
                        data = aesKeyEncrypted,
                        account = unlockHotWallet.storageEncryptionKey(),
                    )
                }

                HotAuth.Biometry -> {
                    authenticatedStorage.store(
                        keyAlias = unlockHotWallet.storageEncryptionKey(),
                        data = aesKey,
                    )
                }
            }

            secureStorage.store(
                data = encrypted,
                account = unlockHotWallet.storageKey(),
            )
        } finally {
            aesKey.fill(0)
        }
    }

    suspend fun changeStore(unlockHotWallet: UnlockHotWallet, newHotAuth: HotAuth) {
        if (unlockHotWallet.auth == newHotAuth) {
            return
        }

        val aesKey = when (val auth = unlockHotWallet.auth) {
            HotAuth.NoAuth -> {
                secureStorage.get(unlockHotWallet.storageEncryptionKey())
                    ?: error("No encryption key found for wallet ${unlockHotWallet.walletId}")
            }

            is HotAuth.Password -> {
                val aesKeyEncrypted = secureStorage.get(unlockHotWallet.storageEncryptionKey())
                    ?: error("No encryption key found for wallet ${unlockHotWallet.walletId}")

                AESEncryptionProtocol.decryptWithPassword(
                    password = auth.value,
                    encryptedData = aesKeyEncrypted,
                ) ?: throw WrongPasswordException()
            }

            HotAuth.Biometry -> {
                authenticatedStorage.get(unlockHotWallet.storageEncryptionKey())
                    ?: error("No private info found for wallet ${unlockHotWallet.walletId}")
            }
        }

        try {
            require(aesKey.size == AES_KEY_SIZE) {
                "Unexpected AES key size: ${aesKey.size}, expected $AES_KEY_SIZE bytes"
            }

            when (newHotAuth) {
                HotAuth.NoAuth -> {
                    secureStorage.store(
                        data = aesKey,
                        account = unlockHotWallet.storageEncryptionKey(),
                    )
                }

                is HotAuth.Password -> {
                    val aesEncrypted = AESEncryptionProtocol.encryptWithPassword(
                        password = newHotAuth.value,
                        content = aesKey,
                    )
                    secureStorage.store(
                        data = aesEncrypted,
                        account = unlockHotWallet.storageEncryptionKey(),
                    )
                }

                HotAuth.Biometry -> {
                    if (unlockHotWallet.auth == HotAuth.NoAuth) {
                        secureStorage.delete(unlockHotWallet.storageEncryptionKey())
                    }

                    authenticatedStorage.store(
                        keyAlias = unlockHotWallet.storageEncryptionKey(),
                        data = aesKey,
                    )
                }
            }
        } finally {
            aesKey.fill(0)
        }
    }

    fun removeBiometryAuth(hotWalletId: HotWalletId): HotWalletId {
        val storageKey = PRIVATE_INFO_PREFIX + hotWalletId.value
        authenticatedStorage.delete(storageKey)
        return hotWalletId.copy(
            authType = when (hotWalletId.authType) {
                HotWalletId.AuthType.Biometry -> HotWalletId.AuthType.Password
                else -> hotWalletId.authType
            },
        )
    }

    fun delete(hotWalletId: HotWalletId) {
        val storageKey = PRIVATE_INFO_PREFIX + hotWalletId.value
        authenticatedStorage.delete(storageKey)
        secureStorage.delete(storageKey)
        secureStorage.delete(ENCRYPTION_KEY_PREFIX + hotWalletId.value)
    }

    fun getContainer(unlockHotWallet: UnlockHotWallet): PrivateInfoContainer {
        return PrivateInfoContainer(
            getPrivateInfo = {
                val encryptedData =
                    secureStorage.get(unlockHotWallet.storageKey())
                        ?: error("No private info found for wallet ${unlockHotWallet.walletId}")

                val aesKey = when (val auth = unlockHotWallet.auth) {
                    HotAuth.NoAuth -> {
                        secureStorage.get(unlockHotWallet.storageEncryptionKey())
                            ?: error("No encryption key found for wallet ${unlockHotWallet.walletId}")
                    }

                    is HotAuth.Password -> {
                        val aesKeyEncrypted = secureStorage.get(unlockHotWallet.storageEncryptionKey())
                            ?: error("No encryption key found for wallet ${unlockHotWallet.walletId}")

                        AESEncryptionProtocol.decryptWithPassword(
                            password = auth.value,
                            encryptedData = aesKeyEncrypted,
                        ) ?: throw WrongPasswordException()
                    }

                    HotAuth.Biometry -> {
                        authenticatedStorage.get(unlockHotWallet.storageEncryptionKey())
                            ?: error("No private info found for wallet ${unlockHotWallet.walletId}")
                    }
                }

                try {
                    AESEncryptionProtocol.decryptAES(
                        rawEncryptionKey = aesKey,
                        encryptedData = encryptedData,
                        associatedData = null,
                    )!!
                } finally {
                    aesKey.fill(0)
                }
            },
        )
    }

    private fun generateAESEncryptionKey(): ByteArray {
        val key = ByteArray(AES_KEY_SIZE)
        SecureRandom().nextBytes(key)
        return key
    }

    private fun UnlockHotWallet.storageKey(): String {
        return PRIVATE_INFO_PREFIX + walletId.value
    }

    private fun UnlockHotWallet.storageEncryptionKey(): String {
        return ENCRYPTION_KEY_PREFIX + walletId.value
    }
}