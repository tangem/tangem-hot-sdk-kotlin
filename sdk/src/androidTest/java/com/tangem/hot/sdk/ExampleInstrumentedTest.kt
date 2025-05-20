package com.tangem.hot.sdk

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.tangem.common.card.EllipticCurve
import com.tangem.common.extensions.toHexString
//import com.tangem.crypto.Bls
import com.tangem.crypto.CryptoUtils

import org.junit.Test
import org.junit.runner.RunWith

import org.junit.Assert.*
import wallet.core.jni.CoinType
import wallet.core.jni.Curve
import wallet.core.jni.HDWallet

/**
 * Instrumented test, which will execute on an Android device.
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
@RunWith(AndroidJUnit4::class)
class ExampleInstrumentedTest {

    init {
        System.loadLibrary("TrustWalletCore")
    }

    @Test
    fun useAppContext() {
        val hdWallet = HDWallet("help major bright ripple goose until endorse air tell bubble finger sure", "")
//        val privateKey = hdWallet.getKeyByCurve(Curve.ED25519, "m/44'/501'/0'")


        // TODO [REDACTED_TASK_KEY]-Hot-Wallet-CI wait for tsdk develop-469 build and uncomment next 3 lines
//        val mkey = Bls.makeMasterKey(hdWallet.seed())
//        val pubKey = Bls.generatePublicKey(mkey)

//        println(pubKey.toHexString())
    }
}