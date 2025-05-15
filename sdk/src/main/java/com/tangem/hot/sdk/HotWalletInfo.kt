package com.tangem.hot.sdk

import com.tangem.common.card.EllipticCurve
import com.tangem.crypto.hdWallet.DerivationPath
import com.tangem.crypto.hdWallet.bip32.ExtendedPublicKey

data class HotWalletInfo(
    val wallets: List<Wallet>,
) {

    data class Wallet(
        val publicKey: ByteArray,
        val chainCode: ByteArray?,
        val curve: EllipticCurve,
        val index: Int,
        val derivedKeys: Map<DerivationPath, ExtendedPublicKey>,
        val extendedPublicKey: ExtendedPublicKey?,
    )
}