package com.tangem.hot.sdk.android.model

import com.tangem.common.card.EllipticCurve
import com.tangem.crypto.hdWallet.bip32.ExtendedPrivateKey
import com.tangem.crypto.hdWallet.bip32.ExtendedPublicKey
import com.tangem.hot.sdk.android.jni.HDNodeJNI

internal class DerivedKeyPair(
    val privateKey: ExtendedPrivateKey,
    val publicKey: ExtendedPublicKey,
    val curve: EllipticCurve,
    val hdNodeJNI: HDNodeJNI? = null, // Optional, used for signing
)