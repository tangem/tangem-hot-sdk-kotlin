package com.tangem.hot.sdk.android

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth
import com.tangem.common.card.EllipticCurve
import com.tangem.common.extensions.toHexString
import com.tangem.crypto.hdWallet.DerivationPath
import com.tangem.hot.sdk.TangemHotSdk
import com.tangem.hot.sdk.model.DeriveWalletRequest
import com.tangem.hot.sdk.model.HotAuth
import com.tangem.hot.sdk.model.MnemonicType
import com.tangem.hot.sdk.model.UnlockHotWallet
import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.time.Duration.Companion.minutes

@RunWith(AndroidJUnit4::class)
class WalletCreationTest {

    @Test
    fun importWallet() {
        val expectedMnemonic =
            "inspire filter clever gauge month island skill raise member visit auto convince"
        val expectedPassphrase = "test-passphrase"

        withPreparedSdk(
            mnemonicString = expectedMnemonic,
            passphrase = expectedPassphrase,
        ) { walletId, hotSdk ->

            val privateInfo = hotSdk.exportMnemonic(
                UnlockHotWallet(walletId, HotAuth.NoAuth)
            )

            Truth.assertThat(
                privateInfo.mnemonic.mnemonicComponents.joinToString(" ")
            ).isEqualTo(expectedMnemonic)

            Truth.assertThat(privateInfo.passphrase)
                .isEqualTo(expectedPassphrase.toCharArray())
        }
    }

    @Test
    fun importWallet_publicKey() {
        val expectedMnemonic =
            "inspire filter clever gauge month island skill raise member visit auto convince"

        withPreparedSdk(
            mnemonicString = expectedMnemonic,
            passphrase = null,
        ) { walletId, hotSdk ->

            val publicKey = hotSdk.derivePublicKey(
                UnlockHotWallet(walletId, HotAuth.NoAuth),
                DeriveWalletRequest(
                    requests = listOf(
                        DeriveWalletRequest.Request(
                            curve = EllipticCurve.Secp256k1,
                            paths = listOf(DerivationPath("m/44'/0'/0'/0/0"))
                        )
                    )
                )
            )

            val seedKey = publicKey.responses.first().seedKey.publicKey
            val derivedKey = publicKey.responses.first().publicKeys.entries.first().value.publicKey

            Truth.assertThat(seedKey.toHexString())
                .isEqualTo("02A77E3C9F106DF94E736BE6A38748F68B86E2DF2DA0B9564614101522E1A246B6")

            Truth.assertThat(derivedKey.toHexString())
                .isEqualTo("0397789B387E2738337687592558464A9FDA31AB71B554FA4C6017A67F10104391")
        }
    }

    @Test
    fun importWallet_publicKey_withPassphrase() {
        val expectedMnemonic =
            "inspire filter clever gauge month island skill raise member visit auto convince"
        val expectedPassphrase = "test-passphrase-123"

        withPreparedSdk(
            mnemonicString = expectedMnemonic,
            passphrase = expectedPassphrase,
        ) { walletId, hotSdk ->

            val publicKey = hotSdk.derivePublicKey(
                UnlockHotWallet(walletId, HotAuth.NoAuth),
                DeriveWalletRequest(
                    requests = listOf(
                        DeriveWalletRequest.Request(
                            curve = EllipticCurve.Secp256k1,
                            paths = listOf(DerivationPath("m/44'/0'/0'/0/0"))
                        )
                    )
                )
            )

            val seedKey = publicKey.responses.first().seedKey.publicKey
            val derivedKey = publicKey.responses.first().publicKeys.entries.first().value.publicKey

            Truth.assertThat(seedKey.toHexString())
                .isEqualTo("0333FCB945B0F53DF4A14708A7B01B196957F1361D151677603484DB79642D838A")

            Truth.assertThat(derivedKey.toHexString())
                .isEqualTo("03C7849E4ED0D0D7139C4F6713EE70BD026668F9359051ADCA062923CFEE3D989B")
        }
    }

    @Test
    fun generateWallet() {
        val scenario = ActivityScenario.launch(MainActivity::class.java)

        scenario.onActivity { activity ->
            val tangemHotSdk = TangemHotSdk.Companion.create(activity)
            runTest(timeout = 10.minutes) {
                val walletId = tangemHotSdk.generateWallet(
                    auth = HotAuth.NoAuth,
                    mnemonicType = MnemonicType.Words12,
                )

                val privateInfo = tangemHotSdk.exportMnemonic(
                    UnlockHotWallet(walletId, HotAuth.NoAuth)
                )

                Truth.assertThat(
                    privateInfo.mnemonic.mnemonicComponents.size
                ).isEqualTo(12)

                Truth.assertThat(privateInfo.passphrase)
                    .isNull()
            }
        }
    }

    @Test
    fun generateWallet_24Words() {
        val scenario = ActivityScenario.launch(MainActivity::class.java)

        scenario.onActivity { activity ->
            val tangemHotSdk = TangemHotSdk.Companion.create(activity)
            runTest(timeout = 10.minutes) {
                val walletId = tangemHotSdk.generateWallet(
                    auth = HotAuth.NoAuth,
                    mnemonicType = MnemonicType.Words24,
                )

                val privateInfo = tangemHotSdk.exportMnemonic(
                    UnlockHotWallet(walletId, HotAuth.NoAuth)
                )

                Truth.assertThat(
                    privateInfo.mnemonic.mnemonicComponents.size
                ).isEqualTo(24)

                Truth.assertThat(privateInfo.passphrase)
                    .isNull()
            }
        }
    }

    @Test
    fun generateWallet_no_pregenerated_mnemonics() {
        val scenario = ActivityScenario.launch(MainActivity::class.java)

        scenario.onActivity { activity ->
            val tangemHotSdk = TangemHotSdk.Companion.create(activity)
            runTest(timeout = 10.minutes) {
                val generatedMnemonics = mutableSetOf<String>()
                val hotWalletIds = mutableSetOf<String>()

                repeat(100) {
                    val walletId = tangemHotSdk.generateWallet(
                        auth = HotAuth.NoAuth,
                        mnemonicType = MnemonicType.Words12,
                    )

                    val privateInfo = tangemHotSdk.exportMnemonic(
                        UnlockHotWallet(walletId, HotAuth.NoAuth)
                    )

                    val mnemonicString = privateInfo.mnemonic.mnemonicComponents.joinToString(" ")
                    generatedMnemonics.add(mnemonicString)
                    hotWalletIds.add(walletId.value)
                }

                Truth.assertThat(generatedMnemonics.size).isEqualTo(100)
                Truth.assertThat(hotWalletIds.size).isEqualTo(100)
            }
        }
    }

    @Test
    fun generateWallet_no_pregenerated_mnemonics_24words() {
        val scenario = ActivityScenario.launch(MainActivity::class.java)

        scenario.onActivity { activity ->
            val tangemHotSdk = TangemHotSdk.Companion.create(activity)
            runTest(timeout = 10.minutes) {
                val generatedMnemonics = mutableSetOf<String>()
                val hotWalletIds = mutableSetOf<String>()

                repeat(100) {
                    val walletId = tangemHotSdk.generateWallet(
                        auth = HotAuth.NoAuth,
                        mnemonicType = MnemonicType.Words24,
                    )

                    val privateInfo = tangemHotSdk.exportMnemonic(
                        UnlockHotWallet(walletId, HotAuth.NoAuth)
                    )

                    val mnemonicString = privateInfo.mnemonic.mnemonicComponents.joinToString(" ")
                    generatedMnemonics.add(mnemonicString)
                    hotWalletIds.add(walletId.value)
                }

                Truth.assertThat(generatedMnemonics.size).isEqualTo(100)
                Truth.assertThat(hotWalletIds.size).isEqualTo(100)
            }
        }
    }

    @Test
    fun walletDeletion() {
        withPreparedSdk { walletId, hotSdk ->
            hotSdk.delete(walletId)

            val result = runCatching {
                hotSdk.exportMnemonic(UnlockHotWallet(walletId, HotAuth.NoAuth))
            }.onFailure {
                Truth.assertThat(it).isInstanceOf(IllegalStateException::class.java)
            }

            Truth.assertThat(result.isFailure).isTrue()
        }
    }
}