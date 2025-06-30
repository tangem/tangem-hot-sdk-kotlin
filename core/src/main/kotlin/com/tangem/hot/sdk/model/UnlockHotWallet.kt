package com.tangem.hot.sdk.model

data class UnlockHotWallet(
    val walletId: HotWalletId,
    val auth: HotAuth,
) {
    init {
        val authMatch = when (walletId.authType) {
            HotWalletId.AuthType.NoPassword -> auth is HotAuth.Password
            HotWalletId.AuthType.Password -> auth is HotAuth.Password || auth is HotAuth.Biometry
            HotWalletId.AuthType.Biometry -> auth is HotAuth.Biometry
        }

        require(authMatch)
    }
}