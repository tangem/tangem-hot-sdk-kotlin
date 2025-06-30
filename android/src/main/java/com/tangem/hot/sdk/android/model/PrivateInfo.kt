package com.tangem.hot.sdk.android.model

import java.nio.ByteBuffer

private const val PACKAGING_VERSION = 1

internal class PrivateInfo(
    val entropy: ByteArray,
    val passphrase: CharArray?,
) {

    fun toByteArray(): ByteArray {
        val byteBuffer =
            ByteBuffer.allocate(1 + Int.SIZE_BYTES * 2 + entropy.size + (passphrase?.size ?: 0))
        byteBuffer.put(PACKAGING_VERSION.toByte())
        byteBuffer.putInt(entropy.size)
        byteBuffer.put(entropy)
        byteBuffer.putInt(passphrase?.size ?: 0)
        passphrase?.let { byteBuffer.put(it.map { it.code.toByte() }.toByteArray()) }
        return byteBuffer.array()
    }

    fun clear() {
        entropy.fill(0)
        passphrase?.fill('\u0000')
    }

    companion object {
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
                    ?.let { it.map { it.toInt().toChar() }.toCharArray() },
            )
        }
    }
}