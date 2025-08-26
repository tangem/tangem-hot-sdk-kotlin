package com.tangem.hot.sdk.android.model

import java.nio.ByteBuffer

private const val PACKAGING_VERSION = 1

internal class PrivateInfo(
    val entropy: ByteArray,
    val passphrase: CharArray?,
) {

    @Suppress("MagicNumber")
    private fun toUtf16be(chars: CharArray): ByteArray {
        val byteArray = ByteArray(chars.size * 2)
        for (i in chars.indices) {
            val code = chars[i].code
            byteArray[2 * i] = (code shr 8).toByte() // high byte
            byteArray[2 * i + 1] = (code and 0xFF).toByte() // low byte
        }
        return byteArray
    }

    fun toByteArray(): ByteArray {
        val byteBuffer =
            ByteBuffer.allocate(1 + Int.SIZE_BYTES * 2 + entropy.size + (passphrase?.size ?: 0) * 2)
        byteBuffer.put(PACKAGING_VERSION.toByte())
        byteBuffer.putInt(entropy.size)
        byteBuffer.put(entropy)
        byteBuffer.putInt((passphrase?.size ?: 0) * 2)
        passphrase?.let { byteBuffer.put(toUtf16be(it)) }
        return byteBuffer.array()
    }

    fun clear() {
        entropy.fill(0)
        passphrase?.fill('\u0000')
    }

    companion object {
        @Suppress("MagicNumber", "UnnecessaryParentheses")
        private fun fromUtf16be(bytes: ByteArray): CharArray {
            require(bytes.size % 2 == 0) { "UTF-16BE byte array must have even length" }

            val chars = CharArray(bytes.size / 2)
            for (i in chars.indices) {
                val hi = bytes[2 * i].toInt() and 0xFF // high byte
                val lo = bytes[2 * i + 1].toInt() and 0xFF // low byte
                chars[i] = ((hi shl 8) or lo).toChar()
            }
            return chars
        }

        fun fromByteArray(data: ByteArray): PrivateInfo {
            val byteBuffer = ByteBuffer.wrap(data)
            val packagingVersion = byteBuffer.get().toInt()

            require(packagingVersion == PACKAGING_VERSION) {
                "Unsupported packaging version: $packagingVersion"
            }

            val entropySize = byteBuffer.int
            val entropy = ByteArray(entropySize)
            byteBuffer.get(entropy)
            val passphraseLength = byteBuffer.int
            val passphrase = ByteArray(passphraseLength)
            if (passphraseLength != 0) {
                byteBuffer.get(passphrase)
            }
            return PrivateInfo(
                entropy = entropy,
                passphrase = passphrase.takeIf { it.isNotEmpty() }
                    ?.let { fromUtf16be(it) },
            )
        }
    }
}