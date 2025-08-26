package com.tangem.hot.sdk.android.crypto

internal object EntropyUtils {

    @Suppress("MagicNumber")
    fun ByteArray.adjustTo16And32Bytes(): ByteArray {
        return when {
            size < 16 -> ByteArray(16 - size) { 0 } + this
            size in 17..31 -> ByteArray(32 - size) { 0 } + this
            size > 32 -> sliceArray(0 until 32)
            else -> this // if exactly 16 or 32 bytes, return as is
        }
    }
}