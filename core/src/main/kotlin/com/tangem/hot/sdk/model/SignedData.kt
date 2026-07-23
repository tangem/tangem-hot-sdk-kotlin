package com.tangem.hot.sdk.model

import com.tangem.common.card.EllipticCurve
import com.tangem.crypto.hdWallet.DerivationPath

class SignedData(
    val curve: EllipticCurve,
    val derivationPath: DerivationPath? = null,
    val signatures: List<ByteArray>,
)