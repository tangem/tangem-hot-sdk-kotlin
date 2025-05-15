package com.tangem.hot.sdk

import com.tangem.common.card.EllipticCurve
import com.tangem.common.extensions.ByteArrayKey
import com.tangem.crypto.bip39.Mnemonic
import com.tangem.crypto.hdWallet.DerivationPath
import com.tangem.crypto.hdWallet.bip32.ExtendedPublicKey
import com.tangem.operations.derivation.ExtendedPublicKeysMap
import wallet.core.jni.StellarPassphrase

interface TangemHotSdk {

    suspend fun importMnemonic(
        mnemonic: Mnemonic,
        passphrase: CharArray?,
        auth: HotAuth.Password,
    ): HotWalletId

    suspend fun generateWallet(
        auth: HotAuth.Password,
        mnemonicType: MnemonicRepository.MnemonicType
    ): HotWalletId

    fun showMnemonic(id: HotWalletId)

    fun exportMnemonic(
        id: HotWalletId,
        auth: HotAuth,
        export: (ByteArray) -> Unit,
    )

    fun getExistingWallets(): List<HotWalletId>

    suspend fun derivePublicKey(
        id: HotWalletId,
        auth: HotAuth,
        request: DeriveWalletRequest,
    ): DerivedPublicKeyResponse

    fun remove(id: HotWalletId)

    suspend fun signHashes(
        id: HotWalletId,
        auth: HotAuth,
        curve: EllipticCurve,
        derivationPath: DerivationPath? = null,
        hashes: List<ByteArray>,
    ): List<ByteArray>

    suspend fun multiSign(
        id: HotWalletId,
        auth: HotAuth,
        curve: EllipticCurve,
        derivationPath: DerivationPath? = null,
        hashes: List<ByteArray>,
    ): Map<ByteArray, ByteArray>
}
