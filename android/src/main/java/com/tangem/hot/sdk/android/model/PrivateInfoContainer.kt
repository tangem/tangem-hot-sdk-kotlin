package com.tangem.hot.sdk.android.model

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.nio.ByteBuffer
import java.security.SecureRandom

internal class PrivateInfoContainer(
    private val secureRandom: SecureRandom = SecureRandom(),
    private val getPrivateInfo: suspend () -> ByteArray,
) {
    private val mutex = Mutex()

    suspend inline fun <reified T> use(usage: suspend PrivateInfoContainer.(privateInfo: PrivateInfo) -> T): T {
        return mutex.withLock {
            var buffer: ByteBuffer? = null
            try {
                buffer = ByteBuffer.wrap(getPrivateInfo.invoke())
                buffer.asReadOnlyBuffer().array().transformToPrivateInfoAndUse {
                    this.usage(it)
                }
            } catch (throwable: Throwable) {
                error("Failed to use private info. Raw error: ${throwable.message}")
            } finally {
                buffer?.let { secureRandom.nextBytes(it.array()) }
            }
        }
    }

    private inline fun <reified T> ByteArray.transformToPrivateInfoAndUse(usage: (PrivateInfo) -> T): T {
        val privateInfo = PrivateInfo.fromByteArray(this)
        return try {
            usage(privateInfo)
        } finally {
            privateInfo.clear()
        }
    }
}