package com.tangem.hot.sdk.android.crypto

internal object EntropyUtils {

    @Suppress("MagicNumber")
    fun ByteArray.adjustToBip39Entropy(): ByteArray {
        val targetSize = when (size) {
            in 0..16 -> 16
            in 17..20 -> 20
            in 21..24 -> 24
            in 25..28 -> 28
            else -> 32 // 29..∞
        }

        return when {
            size < targetSize -> ByteArray(targetSize - size) { 0 } + this
            size > targetSize -> sliceArray(size - targetSize until size)
            else -> this
        }
    }
}