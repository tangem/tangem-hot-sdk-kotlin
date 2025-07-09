package com.tangem.hot.sdk

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.tangem.common.card.EllipticCurve
import com.tangem.common.extensions.hexToBytes
import com.tangem.hot.sdk.android.create
import com.tangem.hot.sdk.model.DataToSign
import com.tangem.hot.sdk.model.HotAuth
import com.tangem.hot.sdk.model.MnemonicType
import com.tangem.hot.sdk.model.UnlockHotWallet
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ExampleInstrumentedTest {

    init {
        System.loadLibrary("TrustWalletCore")
    }

    @Test
    fun testBlsSign() {
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        scenario.onActivity { activity ->
            val tangemHotSdk = TangemHotSdk.create(activity)

            runBlocking {
                val walletId = tangemHotSdk.generateWallet(HotAuth.NoAuth, MnemonicType.Words12)
                tangemHotSdk.signHashes(
                    UnlockHotWallet(walletId = walletId, HotAuth.NoAuth), dataToSign = listOf(
                        DataToSign(
                            curve = EllipticCurve.Secp256k1,
                            derivationPath = null,
                            hashes = listOf(
                                "845A9DF477D88558EB0BDEF833CBE325EDB2451ADE57C30A488C41751396B8B66F212844AF7C1F87C15BBBE70CB26EAB0D46A1EFA0AC3C56A71F79155029151B5081BEB6ECDD652D5149DEE7B69A1D4776CF2372CC44411CF80ACE010B42D0D3".hexToBytes()
                            )
                        )
                    )
                )
            }
        }
    }
}