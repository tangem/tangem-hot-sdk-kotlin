package com.tangem.hot.sdk.android.crypto

import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

private const val PBKDF2_ALGORITHM: String = "PBKDF2WithHmacSHA256"
private const val PBKDF2_MIN_ITERATIONS: Int = 1000
private const val PBKDF2_DEFAULT_ITERATIONS: Int = 600_000

@Suppress("MagicNumber")
internal class PBKDF2KeyStretcher(
    iterations: Int = PBKDF2_DEFAULT_ITERATIONS,
    private val provider: String? = "SC",
) {
    private val internalIterations = maxOf(PBKDF2_MIN_ITERATIONS, iterations)

    fun stretch(salt: ByteArray, password: CharArray, outLengthByte: Int): ByteArray? {
        try {
            return pbkdf2(password, salt, internalIterations, outLengthByte)
        } catch (e: Exception) {
            throw IllegalStateException("could not stretch with pbkdf2", e)
        }
    }

    @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
    private fun pbkdf2(password: CharArray, salt: ByteArray, iterations: Int, outBytes: Int): ByteArray? {
        val spec = PBEKeySpec(password, salt, iterations, outBytes * 8)
        val skf = if (provider != null) {
            SecretKeyFactory.getInstance(
                PBKDF2_ALGORITHM,
                provider,
            )
        } else {
            SecretKeyFactory.getInstance(PBKDF2_ALGORITHM)
        }
        return skf.generateSecret(spec).encoded
    }
}