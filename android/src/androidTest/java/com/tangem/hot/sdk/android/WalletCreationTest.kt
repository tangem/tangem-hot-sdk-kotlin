package com.tangem.hot.sdk.android

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth
import com.tangem.common.CompletionResult
import com.tangem.common.card.EllipticCurve
import com.tangem.common.extensions.toHexString
import com.tangem.common.map
import com.tangem.crypto.bip39.DefaultMnemonic
import com.tangem.crypto.bip39.Wordlist
import com.tangem.crypto.hdWallet.DerivationPath
import com.tangem.hot.sdk.TangemHotSdk
import com.tangem.hot.sdk.model.DeriveWalletRequest
import com.tangem.hot.sdk.model.HotAuth
import com.tangem.hot.sdk.model.MnemonicType
import com.tangem.hot.sdk.model.UnlockHotWallet
import com.tangem.sdk.extensions.getWordlist
import kotlinx.coroutines.test.runTest
import org.bitcoinj.crypto.HDKeyDerivation
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
    fun importWallet_publicKey_15words() {
        val expectedMnemonic =
            "seek penalty caution unique analyst renew alone search increase cube mutual have remind birth bind"

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
                .isEqualTo("03367EFD158FA89CCD648D74FC8F97260F9DC1F3D6FDD098C8CB968F388002567D")

            Truth.assertThat(derivedKey.toHexString())
                .isEqualTo("039724678E5536BB8BC26483EF918D6C97F6787668023704B6C4E12A3C66A7A081")
        }
    }


    @Test
    fun importWallet_publicKey_18words() {
        val expectedMnemonic =
            "mail mistake issue code victory couple rough vessel margin middle awful shine era crisp affair manual donkey neutral"

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
                .isEqualTo("03C7A01A7322A7EA154AF8496062A7250B2B7A3F69F94ABFF1156C5569984D525F")

            Truth.assertThat(derivedKey.toHexString())
                .isEqualTo("0353F098095BADBBA8D0B1A7FFDB6B8B7E9A885CCF691A90BB899FC6485F84C1EC")
        }
    }

    @Test
    fun importWallet_publicKey_21words() {
        val expectedMnemonic =
            "goddess clutch argue resemble unaware balance under electric crime behind gap stuff mean wire peace loop tennis crush invest give focus"

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
                .isEqualTo("031A638BFCD01A5B02D8030C1EDF50F63531BFBDFD9AFAFA563EF3CEC21AC059FD")

            Truth.assertThat(derivedKey.toHexString())
                .isEqualTo("02C876121B6ACD804B9CF723D09CBF04D87E393792BAE8B73387EC3CB2BC576D6D")
        }
    }

    @Test
    fun importWallet_publicKey_24words_against_bitcoinj() {
        val scenario = ActivityScenario.launch(MainActivity::class.java)

        scenario.onActivity { activity ->
            repeat(100) {
                val mnemonicRepository = MnemonicRepository(activity)
                val mnemonicString = mnemonicRepository
                    .generateMnemonic(MnemonicType.Words24)
                    .mnemonicComponents.joinToString(" ") { it.toString() }

                val wordList = Wordlist.Companion.getWordlist(activity)
                val tangemHotSdk = TangemHotSdk.Companion.create(activity)
                val mnemonic = DefaultMnemonic(
                    mnemonic = mnemonicString,
                    wordlist = wordList
                )

                runTest(timeout = 10.minutes) {
                    val walletId = tangemHotSdk.importWallet(
                        mnemonic = mnemonic,
                        passphrase = null,
                        auth = HotAuth.NoAuth
                    )

                    val exportedMnemonic =
                        tangemHotSdk.exportMnemonic(UnlockHotWallet(walletId, HotAuth.NoAuth))

                    Truth.assertThat(
                        exportedMnemonic.mnemonic.mnemonicComponents.joinToString(" ")
                    ).isEqualTo(mnemonicString)

                    val publicKey = tangemHotSdk.derivePublicKey(
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

                    val seedKey = publicKey.responses.first().seedKey

                    val expectedSeed = mnemonic.generateSeed().let {
                        when(it) {
                            is CompletionResult.Failure -> error("")
                            is CompletionResult.Success -> it.data
                        }
                    }

                    Truth.assertThat(seedKey.publicKey.toHexString())
                        .isEqualTo(HDKeyDerivation.createMasterPrivateKey(expectedSeed).pubKey.toHexString())
                }
            }
        }
    }


    @Test
    fun importWallet_publicKey_24words() {
        val expectedMnemonic =
            "steak hurt either real team game torch cancel slab hidden library despair pattern digital pair snow remove narrow floor cattle again minimum domain fossil"

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
                .isEqualTo("03CFAD75FAB6831BECE959DDA4A6992C03E45A3BEE6821BB5D3380D7C054B37901")

            Truth.assertThat(derivedKey.toHexString())
                .isEqualTo("02229732FFC3AF39C94C5B378E71F31E61AE95AD0A8107E4703E2EAC0852F3F42D")
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