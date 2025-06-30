package com.tangem.hot.sdk

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.tangem.common.card.EllipticCurve
import com.tangem.common.extensions.hexToBytes
import com.tangem.common.extensions.toHexString
import com.tangem.crypto.Bls
import com.tangem.crypto.CryptoUtils

import org.junit.Test
import org.junit.runner.RunWith

import org.junit.Assert.*
import wallet.core.jni.CoinType
import wallet.core.jni.Curve
import wallet.core.jni.HDWallet

@RunWith(AndroidJUnit4::class)
class ExampleInstrumentedTest {

    init {
        System.loadLibrary("TrustWalletCore")
    }

    @Test
    fun useAppContext() {
        val hdWallet = HDWallet("help major bright ripple goose until endorse air tell bubble finger sure", "")
        val privateKey = hdWallet.getKeyByCurve(Curve.ED25519, "m/44'/501'/0'")
        val hashToSign = "845A9DF477D88558EB0BDEF833CBE325EDB2451ADE57C30A488C41751396B8B66F212844AF7C1F87C15BBBE70CB26EAB0D46A1EFA0AC3C56A71F79155029151B5081BEB6ECDD652D5149DEE7B69A1D4776CF2372CC44411CF80ACE010B42D0D3".hexToBytes()
        val expectedSignature = "A7CA68B8B565930150C6FA63395B38B9D80954463DE0C623022BEDB884C686DBCCEBAFAC9FE20C191D6A90B275A88EA50BDC3BCED6A7AD24FF40909F3E14D5DE28AFBF62D56ACD67C22D6262ED1B118004FBD55B211AC2391D5BA76CCEA978B5".hexToBytes()
        val actualSign = "A5001574D493871A1B587B25BB0083C9679794B60B0B9F6D4C1AE21ABB53106482455976ED9A6BD2A8A560E40E74AAD30F10E75322F947F4F2C554DFDB99E245EBCE59B06861A90D49F367E80EC930246BAD0CF15699A1394E7E6A87FA993747".hexToBytes()

        val mkey = Bls.makeMasterKey(hdWallet.seed())

        val signature = Bls.signHash(hashToSign, mkey)

        assertArrayEquals(expectedSignature, signature)
    }
}