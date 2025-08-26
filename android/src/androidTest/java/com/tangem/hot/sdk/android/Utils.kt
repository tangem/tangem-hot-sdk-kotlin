package com.tangem.hot.sdk.android

import androidx.test.core.app.ActivityScenario
import com.tangem.crypto.bip39.DefaultMnemonic
import com.tangem.crypto.bip39.Wordlist
import com.tangem.hot.sdk.TangemHotSdk
import com.tangem.hot.sdk.model.HotAuth
import com.tangem.hot.sdk.model.HotWalletId
import com.tangem.sdk.extensions.getWordlist
import kotlinx.coroutines.test.runTest
import kotlin.time.Duration.Companion.minutes

fun withPreparedSdk(
    mnemonicString: String = "inspire filter clever gauge month island skill raise member visit auto convince",
    passphrase: String? = null,
    action: suspend (HotWalletId, TangemHotSdk) -> Unit
) {
    val scenario = ActivityScenario.launch(MainActivity::class.java)

    scenario.onActivity { activity ->
        val wordList = Wordlist.Companion.getWordlist(activity)
        val tangemHotSdk = TangemHotSdk.Companion.create(activity)
        val mnemonic = DefaultMnemonic(
            mnemonic = mnemonicString,
            wordlist = wordList
        )
        runTest(timeout = 10.minutes) {
            val walletId = tangemHotSdk.importWallet(
                mnemonic = mnemonic,
                passphrase = passphrase?.toCharArray(),
                auth = HotAuth.NoAuth
            )
            action(walletId, tangemHotSdk)
        }
    }
}