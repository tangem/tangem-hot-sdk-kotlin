package com.tangem.hot.sdk

import com.tangem.common.extensions.toHexString
import com.tangem.hot.sdk.ByteArrayEncodingProtocol.decryptWithPassword
import com.tangem.hot.sdk.ByteArrayEncodingProtocol.encryptWithPassword
import org.junit.Test

class ByteArrayEncodingProtocolTest {

    @Test
    fun encrypt_decrypt() {
        val mnemonic = "hello hello hello 2"
        val password = "1234"
        val encrypted = encryptWithPassword(
            password.toCharArray(),
            mnemonic.encodeToByteArray()
        )

        val decrypted = decryptWithPassword(
            password.toCharArray(),
            encrypted
        )

        println(encrypted.toHexString())
        println(decrypted?.toString(Charsets.UTF_8))
    }
}