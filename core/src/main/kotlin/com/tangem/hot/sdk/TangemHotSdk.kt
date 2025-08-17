package com.tangem.hot.sdk

import com.tangem.crypto.bip39.Mnemonic
import com.tangem.hot.sdk.model.DataToSign
import com.tangem.hot.sdk.model.DeriveWalletRequest
import com.tangem.hot.sdk.model.DerivedPublicKeyResponse
import com.tangem.hot.sdk.model.HotAuth
import com.tangem.hot.sdk.model.HotWalletId
import com.tangem.hot.sdk.model.MnemonicType
import com.tangem.hot.sdk.model.SeedPhrasePrivateInfo
import com.tangem.hot.sdk.model.SignedData
import com.tangem.hot.sdk.model.UnlockHotWallet

interface TangemHotSdk {

    suspend fun importWallet(mnemonic: Mnemonic, passphrase: CharArray?, auth: HotAuth): HotWalletId

    suspend fun generateWallet(auth: HotAuth, mnemonicType: MnemonicType): HotWalletId

    suspend fun exportMnemonic(unlockHotWallet: UnlockHotWallet): SeedPhrasePrivateInfo

    suspend fun exportBackup(unlockHotWallet: UnlockHotWallet): ByteArray

    suspend fun delete(id: HotWalletId)

    suspend fun changeAuth(unlockHotWallet: UnlockHotWallet, auth: HotAuth): HotWalletId

    suspend fun removeBiometryAuthIfPresented(id: HotWalletId): HotWalletId

    suspend fun derivePublicKey(
        unlockHotWallet: UnlockHotWallet,
        request: DeriveWalletRequest,
    ): DerivedPublicKeyResponse

    suspend fun signHashes(unlockHotWallet: UnlockHotWallet, dataToSign: List<DataToSign>): List<SignedData>

    companion object
}