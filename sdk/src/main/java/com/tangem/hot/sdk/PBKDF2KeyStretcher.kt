package com.tangem.hot.sdk

import android.os.StrictMode
import com.tangem.common.authentication.keystore.KeystoreManager
import com.tangem.crypto.EncryptionHelper
import java.security.NoSuchAlgorithmException
import java.security.Provider
import java.security.spec.InvalidKeySpecException
import javax.crypto.EncryptedPrivateKeyInfo
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

class PBKDF2KeyStretcher(
    iterations: Int = PBKDF2_DEFAULT_ITERATIONS,
    private val provider: Provider? = null
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
    private fun pbkdf2(
        password: CharArray,
        salt: ByteArray,
        iterations: Int,
        outBytes: Int
    ): ByteArray? {
//        StrictMode.noteSlowCall("pbkdf2 is a very expensive call and should not be done on the main thread")
        val spec = PBEKeySpec(password, salt, iterations, outBytes * 8)
        val skf = if (provider != null) {
            SecretKeyFactory.getInstance(
                PBKDF2_ALGORITHM,
                provider
            )
        } else {
            SecretKeyFactory.getInstance(PBKDF2_ALGORITHM)
        }
        return skf.generateSecret(spec).encoded
    }

    private companion object {
        const val PBKDF2_ALGORITHM: String = "PBKDF2WithHmacSHA1"
        const val PBKDF2_MIN_ITERATIONS: Int = 1000
        const val PBKDF2_DEFAULT_ITERATIONS: Int = 10000
    }
}