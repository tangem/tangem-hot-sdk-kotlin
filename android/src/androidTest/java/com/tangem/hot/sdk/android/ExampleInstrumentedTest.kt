package com.tangem.hot.sdk.android

import android.util.Log
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth
import com.tangem.common.card.EllipticCurve
import com.tangem.common.extensions.hexToBytes
import com.tangem.common.extensions.toHexString
import com.tangem.crypto.bip39.DefaultMnemonic
import com.tangem.crypto.bip39.Wordlist
import com.tangem.crypto.hdWallet.DerivationPath
import com.tangem.hot.sdk.TangemHotSdk
import com.tangem.hot.sdk.model.DataToSign
import com.tangem.hot.sdk.model.DeriveWalletRequest
import com.tangem.hot.sdk.model.HotAuth
import com.tangem.hot.sdk.model.HotWalletId
import com.tangem.hot.sdk.model.UnlockHotWallet
import com.tangem.sdk.extensions.getWordlist
import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ExampleInstrumentedTest {

    private fun withPreparedSdk(
        action: suspend (HotWalletId, TangemHotSdk) -> Unit
    ) {
        val scenario = ActivityScenario.launch(MainActivity::class.java)

        scenario.onActivity { activity ->
            val wordList = Wordlist.Companion.getWordlist(activity)
            val tangemHotSdk = TangemHotSdk.Companion.create(activity)
            val mnemonic = DefaultMnemonic(
                "inspire filter clever gauge month island skill raise member visit auto convince",
                wordList
            )
            runTest {
                val walletId = tangemHotSdk.importWallet(
                    mnemonic = mnemonic,
                    passphrase = null,
                    auth = HotAuth.NoAuth
                )
                action(walletId, tangemHotSdk)
            }
        }
    }

    @Test
    fun testCardanoDerivation() {
        withPreparedSdk { walletId, hotSdk ->
            val result = hotSdk.derivePublicKey(
                unlockHotWallet = UnlockHotWallet(walletId = walletId, HotAuth.NoAuth),
                request = DeriveWalletRequest(
                    requests = listOf(
                        DeriveWalletRequest.Request(
                            curve = EllipticCurve.Ed25519,
                            paths = listOf(
                                DerivationPath("m/1852'/1815'/0'/0/0")
                            )
                        )
                    )
                )
            )

            val seedKey = result.responses.first().seedKey
            val derivedKey = result.responses.first().publicKeys.entries.first().value

            Truth.assertThat(seedKey.publicKey)
                .isEqualTo("304EF41EED31AC1F04ADFDE3183B3E82107BC2B0B05656101212A2D80F976196".hexToBytes())

            Truth.assertThat(derivedKey.publicKey)
                .isEqualTo("C8C21EAF4C8DE323027CF4FD29923FE47E8E712F8020DB6429B53BB4F90DE1FA".hexToBytes())
        }
    }

    @Test
    fun testEdSignSolana() {
        withPreparedSdk { walletId, hotSdk ->
            val result = hotSdk.signHashes(
                unlockHotWallet = UnlockHotWallet(walletId = walletId, HotAuth.NoAuth),
                dataToSign = listOf(
                    DataToSign(
                        curve = EllipticCurve.Ed25519Slip0010,
                        derivationPath = DerivationPath("m/44'/501'/0'"),
                        hashes = listOf(
                            "D2B3F8A1C4E0F5B6A7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9".hexToBytes()
                        )
                    )
                ),
            )

            val signature = result.first().signatures.first()

            Truth.assertThat(
                signature
            ).isEqualTo("64E55FD5F27D0E217C0D682D7182D744BFB5A85E7DC9B5DB02FA0C862505675D51D37CC270A4A2DC2F8C6C598B9898C6FCF4F67CF80816A89EF57A66626B390E".hexToBytes())
        }
    }
}