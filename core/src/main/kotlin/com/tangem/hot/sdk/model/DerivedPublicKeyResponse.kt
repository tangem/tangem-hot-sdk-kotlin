package com.tangem.hot.sdk.model

import com.tangem.common.card.EllipticCurve
import com.tangem.crypto.hdWallet.DerivationPath

data class DerivedPublicKeyResponse(
    val responses: List<ResponseEntry>,
) {

    data class ResponseEntry(
        val curve: EllipticCurve,
        val publicKeys: Map<DerivationPath, ByteArray>,
    )
}