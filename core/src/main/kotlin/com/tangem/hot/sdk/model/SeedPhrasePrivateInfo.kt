package com.tangem.hot.sdk.model

import com.tangem.crypto.bip39.Mnemonic

class SeedPhrasePrivateInfo(
    val mnemonic: Mnemonic,
    val passphrase: CharArray?,
)