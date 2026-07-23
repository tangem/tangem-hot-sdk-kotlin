package com.tangem.hot.sdk.model

import com.tangem.common.card.EllipticCurve
import com.tangem.crypto.hdWallet.DerivationPath
import com.tangem.crypto.hdWallet.bip32.ExtendedPublicKey

data class DerivedPublicKeyResponse(
    val responses: List<ResponseEntry>,
) {

    data class ResponseEntry(
        val curve: EllipticCurve,
        val seedKey: ExtendedPublicKey,
        val publicKeys: Map<DerivationPath, ExtendedPublicKey>,
    )
}