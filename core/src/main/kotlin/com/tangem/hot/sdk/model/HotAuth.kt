package com.tangem.hot.sdk.model

sealed class HotAuth {
    data object NoAuth : HotAuth()
    class Password(val value: CharArray) : HotAuth()
    data object Biometry : HotAuth()
}