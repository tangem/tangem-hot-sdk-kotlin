package com.tangem.hot.sdk.model

import kotlinx.serialization.Serializable

@Serializable
data class HotWalletId(
    val value: String,
    val authType: AuthType,
) {
    enum class AuthType {
        NoPassword,
        Password,
        Biometry,
    }
}