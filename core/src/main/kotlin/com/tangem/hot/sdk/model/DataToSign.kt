package com.tangem.hot.sdk.model

import com.tangem.common.card.EllipticCurve
import com.tangem.crypto.hdWallet.DerivationPath

class DataToSign(
    val curve: EllipticCurve,
    val derivationPath: DerivationPath? = null,
    val hashes: List<ByteArray>,
)