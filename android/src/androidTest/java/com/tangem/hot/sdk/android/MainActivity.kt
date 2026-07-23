package com.tangem.hot.sdk.android

import androidx.fragment.app.FragmentActivity
import com.tangem.crypto.CryptoUtils

class MainActivity : FragmentActivity() {

    init {
        CryptoUtils.initCrypto()
    }

    // This is a placeholder for the main activity of the Android application.
    // It can be used to initialize the Tangem Hot SDK or perform other setup tasks.
}