package com.tangem.hot.sdk

sealed class HotAuth {
    class Password(val value: CharArray) : HotAuth()
    data object Biometry : HotAuth()
}