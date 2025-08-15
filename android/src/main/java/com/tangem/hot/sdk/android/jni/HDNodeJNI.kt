package com.tangem.hot.sdk.android.jni

internal class HDNodeJNI private constructor(
    private var nativeHandle: Long,
) {

    init {
        GenericPhantomReference.register(this, nativeHandle, ::destroyNative)
    }

    var depth: Int
        get() = getDepthNative(nativeHandle)
        set(value) {
            setDepthNative(nativeHandle, value)
        }

    var childNum: Int
        get() = getChildNum(nativeHandle)
        set(value) {
            setChildNum(nativeHandle, value)
        }

    var chainCode: ByteArray
        get() = getChainCodeNative(nativeHandle)
        set(value) {
            setChainCodeNative(nativeHandle, value)
        }

    var privateKey: ByteArray
        get() = getPrivateKeyNative(nativeHandle)
        set(value) {
            setPrivateKeyNative(nativeHandle, value)
        }

    var publicKey: ByteArray
        get() = getPublicKeyNative(nativeHandle)
        set(value) {
            setPublicKeyNative(nativeHandle, value)
        }

    external fun fingerprint(): ByteArray

    fun destroyNative() {
        if (nativeHandle != 0L) {
            destroyNative(nativeHandle)
            nativeHandle = 0L
        }
    }

    companion object {
        init {
            System.loadLibrary("TrezorCrypto")
        }

        @JvmStatic
        fun create(): HDNodeJNI {
            val handle = createNative()
            require(handle != 0L) { "Failed to create native HDNode" }
            return HDNodeJNI(handle)
        }

        @JvmStatic private external fun createNative(): Long

        @JvmStatic private external fun destroyNative(handle: Long)

        @JvmStatic private external fun getDepthNative(handle: Long): Int

        @JvmStatic private external fun setDepthNative(handle: Long, value: Int): Int

        @JvmStatic private external fun getChildNum(handle: Long): Int

        @JvmStatic private external fun setChildNum(handle: Long, value: Int): Int

        @JvmStatic private external fun getChainCodeNative(handle: Long): ByteArray

        @JvmStatic private external fun setChainCodeNative(handle: Long, value: ByteArray): Int

        @JvmStatic private external fun getPrivateKeyNative(handle: Long): ByteArray

        @JvmStatic private external fun setPrivateKeyNative(handle: Long, value: ByteArray): Int

        @JvmStatic private external fun getPublicKeyNative(handle: Long): ByteArray

        @JvmStatic private external fun setPublicKeyNative(handle: Long, value: ByteArray): Int
    }
}