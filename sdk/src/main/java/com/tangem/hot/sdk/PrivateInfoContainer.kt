package com.tangem.hot.sdk

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.nio.ByteBuffer
import java.security.SecureRandom

internal class PrivateInfoContainer(
    private val secureRandom: SecureRandom = SecureRandom(),
    private val getPrivateInfo: suspend () -> ByteArray
) {
    private val mutex = Mutex()

    suspend inline fun <reified T> use(
        usage: suspend (privateInfo: ByteArray) -> T
    ): T {
        mutex.withLock {
            var buffer: ByteBuffer? = null
            try {
                var privateInfo = getPrivateInfo.invoke()
                buffer = ByteBuffer.wrap(privateInfo)
                return usage(buffer.asReadOnlyBuffer().array())
            } catch (ex: Exception) {
                error("Failed to use private info")
            } finally {
                buffer?.let { secureRandom.nextBytes(it.array()) }
            }
        }
    }
}