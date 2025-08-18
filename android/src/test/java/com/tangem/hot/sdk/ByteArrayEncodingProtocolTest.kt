package com.tangem.hot.sdk

import com.tangem.common.extensions.toHexString
import com.tangem.crypto.CryptoUtils
import com.tangem.hot.sdk.android.crypto.AESEncryptionProtocol.decryptWithPassword
import com.tangem.hot.sdk.android.crypto.AESEncryptionProtocol.encryptWithPassword
import org.junit.Test

class ByteArrayEncodingProtocolTest {

    init {
        CryptoUtils.initCrypto()
    }

    @Test
    fun encrypt_decrypt() {
        val mnemonic = "hello hello hello 2"
        val password = "1234"
        val encrypted = encryptWithPassword(
            password.toCharArray(),
            mnemonic.encodeToByteArray(),
        )

        val decrypted = decryptWithPassword(
            password.toCharArray(),
            encrypted,
        )

        println(encrypted.toHexString())
        println(decrypted?.toString(Charsets.UTF_8))
    }
}