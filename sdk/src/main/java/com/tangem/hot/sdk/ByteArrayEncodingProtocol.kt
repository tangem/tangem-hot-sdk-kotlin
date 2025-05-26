package com.tangem.hot.sdk

import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object ByteArrayEncodingProtocol {

    private const val STRETCHED_PASSWORD_LENGTH_BYTES = 32
    private const val ENCODE_SCHEME_VERSION = 1
    private const val ALGORITHM = "AES/GCM/NoPadding"
    private const val TAG_LENGTH_BIT = 128
    private const val IV_LENGTH_BYTE = 12
    private const val SALT_SIZE = 16

    fun encryptWithPassword(password: CharArray, content: ByteArray): ByteArray {
        fun generateSalt(): ByteArray {
            val array = ByteArray(SALT_SIZE)
            val sr = SecureRandom()
            sr.nextBytes(array)
            return array
        }

        val contentSalt = generateSalt()
        val stretched =
            PBKDF2KeyStretcher().stretch(contentSalt, password, STRETCHED_PASSWORD_LENGTH_BYTES)

        return encode(contentSalt, encrypt(stretched!!, content, contentSalt))
    }

    fun decryptWithPassword(password: CharArray, encryptedData: ByteArray): ByteArray? {
        val (salt, encrypted) = decode(encryptedData)
        val stretched =
            PBKDF2KeyStretcher().stretch(salt, password, STRETCHED_PASSWORD_LENGTH_BYTES)

        return decrypt(stretched!!, encrypted, salt)
    }

    private fun encode(salt: ByteArray, encryptedData: ByteArray): ByteArray {
        val byteBuffer =
            ByteBuffer.allocate(1 + Int.SIZE_BYTES * 2 + salt.size + encryptedData.size)
        byteBuffer.put(ENCODE_SCHEME_VERSION.toByte())
        byteBuffer.putInt(salt.size)
        byteBuffer.put(salt)
        byteBuffer.putInt(encryptedData.size)
        byteBuffer.put(encryptedData)
        return byteBuffer.array()
    }

    private fun decode(encodedData: ByteArray): Pair<ByteArray, ByteArray> {
        val byteBuffer = ByteBuffer.wrap(encodedData)
        val version = byteBuffer.get()
        require(version == ENCODE_SCHEME_VERSION.toByte()) {
            "Unsupported encoding scheme version: $version"
        }
        val saltLength = byteBuffer.int
        val salt = ByteArray(saltLength)
        byteBuffer.get(salt)
        val encryptedLength = byteBuffer.int
        val encrypted = ByteArray(encryptedLength)
        byteBuffer.get(encrypted)
        return Pair(salt, encrypted)
    }

    @Suppress("MagicNumber")
    private fun encrypt(rawEncryptionKey: ByteArray, rawData: ByteArray, associatedData: ByteArray?): ByteArray {
        require(rawEncryptionKey.size >= 16) { "key length must be longer than 16 bytes" }

        var iv: ByteArray? = null
        var encrypted: ByteArray? = null
        try {
            iv = ByteArray(IV_LENGTH_BYTE)
            SecureRandom().nextBytes(iv)

            val cipherEnc: Cipher = Cipher.getInstance(ALGORITHM)
            cipherEnc.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(rawEncryptionKey, "AES"),
                GCMParameterSpec(TAG_LENGTH_BIT, iv),
            )

            if (associatedData != null) {
                cipherEnc.updateAAD(associatedData)
            }

            encrypted = cipherEnc.doFinal(rawData)

            val byteBuffer = ByteBuffer.allocate(1 + iv.size + encrypted.size)
            byteBuffer.put(iv.size.toByte())
            byteBuffer.put(iv)
            byteBuffer.put(encrypted)
            return byteBuffer.array()
        } finally {
            iv?.let { SecureRandom().nextBytes(it) }
            encrypted?.let { SecureRandom().nextBytes(it) }
        }
    }

    @Suppress("MagicNumber")
    private fun decrypt(
        rawEncryptionKey: ByteArray,
        encryptedData: ByteArray,
        associatedData: ByteArray?,
    ): ByteArray? {
        val initialOffset = 1
        val ivLength = encryptedData[0].toInt()

        check(!(ivLength != 12 && ivLength != 16)) { "Unexpected iv length" }

        val cipherDec: Cipher = Cipher.getInstance(ALGORITHM)
        cipherDec.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(rawEncryptionKey, "AES"),
            GCMParameterSpec(
                TAG_LENGTH_BIT,
                encryptedData,
                initialOffset,
                ivLength,
            ),
        )

        if (associatedData != null) {
            cipherDec.updateAAD(associatedData)
        }

        return cipherDec.doFinal(
            encryptedData,
            initialOffset + ivLength,
            encryptedData.size - (initialOffset + ivLength),
        )
    }
}