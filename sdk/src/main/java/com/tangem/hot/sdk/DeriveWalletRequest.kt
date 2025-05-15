package com.tangem.hot.sdk

import com.tangem.common.card.EllipticCurve
import com.tangem.crypto.hdWallet.DerivationPath

data class DeriveWalletRequest(
    val requests: List<Request>
) {
    data class Request(
        val curve: EllipticCurve,
        val paths: List<DerivationPath>
    )
}