package com.tangem.hot.sdk.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth
import com.tangem.common.card.EllipticCurve
import com.tangem.common.extensions.toHexString
import com.tangem.crypto.hdWallet.DerivationPath
import com.tangem.crypto.hdWallet.HDWalletError
import com.tangem.hot.sdk.model.DeriveWalletRequest
import com.tangem.hot.sdk.model.HotAuth
import com.tangem.hot.sdk.model.UnlockHotWallet
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DerivationOperationTest {

    @Test
    fun testDerivationOperation() {
        withPreparedSdk { walletId, hotSdk ->
            val result = hotSdk.derivePublicKey(
                unlockHotWallet = UnlockHotWallet(walletId = walletId, HotAuth.NoAuth),
                request = DeriveWalletRequest(
                    requests = listOf(
                        DeriveWalletRequest.Request(
                            curve = EllipticCurve.Secp256k1,
                            paths = listOf(
                                DerivationPath("m/44'/60'/0'/0/0"),
                                DerivationPath("m/44'/60'/0'/0/1"),
                            )
                        )
                    )
                )
            )

            val derivedKeys = result.responses.first().publicKeys
            Truth.assertThat(derivedKeys.size).isEqualTo(2)

            val firstKey = derivedKeys[DerivationPath("m/44'/60'/0'/0/0")]
            val secondKey = derivedKeys[DerivationPath("m/44'/60'/0'/0/1")]

            Truth.assertThat(firstKey?.publicKey?.toHexString())
                .isEqualTo("0261925D9B6BE76EAEE79AA0F3B7A572985D4A17557432EA40C41BFD39E8C85ED9")
            Truth.assertThat(secondKey?.publicKey?.toHexString())
                .isEqualTo("02618D06D71A86D2C2A936C18449E37E0D9342D5FBFD93A6C560A761DD34CF9908")
        }
    }

    @Test
    fun wrongDerivationPathFormat() {
        withPreparedSdk { walletId, hotSdk ->
            val exception = runCatching {
                hotSdk.derivePublicKey(
                    unlockHotWallet = UnlockHotWallet(walletId = walletId, HotAuth.NoAuth),
                    request = DeriveWalletRequest(
                        requests = listOf(
                            DeriveWalletRequest.Request(
                                curve = EllipticCurve.Secp256k1,
                                paths = listOf(
                                    DerivationPath("44'/60'/0'/0/0"), // should start with "m/"
                                )
                            )
                        )
                    )
                )
            }.exceptionOrNull()

            Truth.assertThat(exception).isInstanceOf(HDWalletError.WrongPath::class.java)
        }
    }

    @Test
    fun derivation_secp256k1() {
        withPreparedSdk { walletId, hotSdk ->
            val result = hotSdk.derivePublicKey(
                unlockHotWallet = UnlockHotWallet(walletId = walletId, HotAuth.NoAuth),
                request = DeriveWalletRequest(
                    requests = listOf(
                        DeriveWalletRequest.Request(
                            curve = EllipticCurve.Secp256k1,
                            paths = listOf(
                                DerivationPath("m/44'/123'/0'/0/0"),
                            ),
                        )
                    )
                )
            )

            val entry = result.responses.first()
            Truth.assertThat(entry.curve).isEqualTo(EllipticCurve.Secp256k1)

            Truth.assertThat(entry.seedKey.publicKey.toHexString())
                .isEqualTo("02A77E3C9F106DF94E736BE6A38748F68B86E2DF2DA0B9564614101522E1A246B6")

            val derivedKey = entry.publicKeys[DerivationPath("m/44'/123'/0'/0/0")]
            Truth.assertThat(derivedKey?.publicKey?.toHexString())
                .isEqualTo("023C04CFCEA3F7382BF9BF14EF6D5735EC9E2065840743D1B71BD87A8395634A62")
        }
    }

    @Test
    fun derivation_bls12381() {
        withPreparedSdk { walletId, hotSdk ->
            val result = hotSdk.derivePublicKey(
                unlockHotWallet = UnlockHotWallet(walletId = walletId, HotAuth.NoAuth),
                request = DeriveWalletRequest(
                    requests = listOf(
                        DeriveWalletRequest.Request(
                            curve = EllipticCurve.Bls12381G2,
                            paths = listOf(
                                DerivationPath("m/12381/3600/0/0/0"),
                            ),
                        )
                    )
                )
            )

            val entry = result.responses.first()
            Truth.assertThat(entry.curve).isEqualTo(EllipticCurve.Bls12381G2)
            val seedKey = entry.seedKey.publicKey
            Truth.assertThat(seedKey.toHexString())
                .isEqualTo("96FE65B72234DD76D5E8B0585C5FC6D4651E85FA1086CD4E9290F1303176606A430BD32B5106F49F461C022F75E37ADE")
            val derivedKey = entry.publicKeys[DerivationPath("m/12381/3600/0/0/0")]
            Truth.assertThat(derivedKey?.publicKey?.toHexString())
                .isEqualTo("96FE65B72234DD76D5E8B0585C5FC6D4651E85FA1086CD4E9290F1303176606A430BD32B5106F49F461C022F75E37ADE")
        }
    }

    @Test
    fun derivation_ed25519_slip0010() {
        withPreparedSdk { walletId, hotSdk ->
            val result = hotSdk.derivePublicKey(
                unlockHotWallet = UnlockHotWallet(walletId = walletId, HotAuth.NoAuth),
                request = DeriveWalletRequest(
                    requests = listOf(
                        DeriveWalletRequest.Request(
                            curve = EllipticCurve.Ed25519Slip0010,
                            paths = listOf(
                                DerivationPath("m/44'/501'/0'/0'"),
                            ),
                        )
                    )
                )
            )

            val entry = result.responses.first()
            Truth.assertThat(entry.curve).isEqualTo(EllipticCurve.Ed25519Slip0010)
            Truth.assertThat(entry.publicKeys.size).isEqualTo(1)
            val derivedKey = entry.publicKeys[DerivationPath("m/44'/501'/0'/0'")]

            Truth.assertThat(entry.seedKey.publicKey.toHexString())
                .isEqualTo("097E2664A73D9C344F2D3873CEC07AA7829E3EAC1A19A48C32D242312C98C7C6")
            Truth.assertThat(derivedKey?.publicKey?.toHexString())
                .isEqualTo("E36E90426BE87AB8BD9DA4FF375C6A5430F22EC2866A01793D268C124B893064")
        }
    }

    @Test
    fun derivation_ed25519() {
        withPreparedSdk { walletId, hotSdk ->
            val result = hotSdk.derivePublicKey(
                unlockHotWallet = UnlockHotWallet(walletId = walletId, HotAuth.NoAuth),
                request = DeriveWalletRequest(
                    requests = listOf(
                        DeriveWalletRequest.Request(
                            curve = EllipticCurve.Ed25519,
                            paths = listOf(
                                DerivationPath("m/44'/501'/0'/0'"),
                            ),
                        )
                    )
                )
            )

            val entry = result.responses.first()
            Truth.assertThat(entry.curve).isEqualTo(EllipticCurve.Ed25519)
            Truth.assertThat(entry.publicKeys.size).isEqualTo(1)
            val derivedKey = entry.publicKeys[DerivationPath("m/44'/501'/0'/0'")]

            Truth.assertThat(entry.seedKey.publicKey.toHexString())
                .isEqualTo("304EF41EED31AC1F04ADFDE3183B3E82107BC2B0B05656101212A2D80F976196")

            Truth.assertThat(derivedKey?.publicKey?.toHexString())
                .isEqualTo("6CB418F453A8390278DC2AE9CD7FB8F6C4FF888C4DCEA7E40F129690C1D483C4")
        }
    }

    @Test
    fun derivation_multipleCurves() {
        withPreparedSdk { walletId, hotSdk ->
            val result = hotSdk.derivePublicKey(
                unlockHotWallet = UnlockHotWallet(walletId = walletId, HotAuth.NoAuth),
                request = DeriveWalletRequest(
                    requests = listOf(
                        DeriveWalletRequest.Request(
                            curve = EllipticCurve.Secp256k1,
                            paths = listOf(
                                DerivationPath("m/44'/60'/0'/0/0"),
                            ),
                        ),
                        DeriveWalletRequest.Request(
                            curve = EllipticCurve.Bls12381G2,
                            paths = listOf(
                                DerivationPath("m/12381/3600/0/0/0"),
                            ),
                        ),
                        DeriveWalletRequest.Request(
                            curve = EllipticCurve.Ed25519Slip0010,
                            paths = listOf(
                                DerivationPath("m/44'/501'/0'/0'"),
                            ),
                        ),
                        DeriveWalletRequest.Request(
                            curve = EllipticCurve.Ed25519,
                            paths = listOf(
                                DerivationPath("m/44'/501'/0'/0'"),
                            ),
                        ),
                    )
                )
            )

            Truth.assertThat(result.responses.size).isEqualTo(4)

            val secp256k1Entry = result.responses.first { it.curve == EllipticCurve.Secp256k1 }
            Truth.assertThat(secp256k1Entry.seedKey.publicKey.toHexString())
                .isEqualTo("02A77E3C9F106DF94E736BE6A38748F68B86E2DF2DA0B9564614101522E1A246B6")
            val secp256k1DerivedKey = secp256k1Entry.publicKeys[DerivationPath("m/44'/60'/0'/0/0")]
            Truth.assertThat(secp256k1DerivedKey?.publicKey?.toHexString())
                .isEqualTo("0261925D9B6BE76EAEE79AA0F3B7A572985D4A17557432EA40C41BFD39E8C85ED9")

            val bls12381Entry = result.responses.first { it.curve == EllipticCurve.Bls12381G2 }
            Truth.assertThat(bls12381Entry.seedKey.publicKey.toHexString())
                .isEqualTo("96FE65B72234DD76D5E8B0585C5FC6D4651E85FA1086CD4E9290F1303176606A430BD32B5106F49F461C022F75E37ADE")
            val bls12381DerivedKey = bls12381Entry.publicKeys[DerivationPath("m/12381/3600/0/0/0")]
            Truth.assertThat(bls12381DerivedKey?.publicKey?.toHexString())
                .isEqualTo("96FE65B72234DD76D5E8B0585C5FC6D4651E85FA1086CD4E9290F1303176606A430BD32B5106F49F461C022F75E37ADE")
            val ed25519Slip0010Entry =
                result.responses.first { it.curve == EllipticCurve.Ed25519Slip0010 }
            Truth.assertThat(ed25519Slip0010Entry.seedKey.publicKey.toHexString())
                .isEqualTo("097E2664A73D9C344F2D3873CEC07AA7829E3EAC1A19A48C32D242312C98C7C6")
            val ed25519Slip0010DerivedKey =
                ed25519Slip0010Entry.publicKeys[DerivationPath("m/44'/501'/0'/0'")]
            Truth.assertThat(ed25519Slip0010DerivedKey?.publicKey?.toHexString())
                .isEqualTo("E36E90426BE87AB8BD9DA4FF375C6A5430F22EC2866A01793D268C124B893064")
            val ed25519Entry = result.responses.first { it.curve == EllipticCurve.Ed25519 }
            Truth.assertThat(ed25519Entry.seedKey.publicKey.toHexString())
                .isEqualTo("304EF41EED31AC1F04ADFDE3183B3E82107BC2B0B05656101212A2D80F976196")
            val ed25519DerivedKey = ed25519Entry.publicKeys[DerivationPath("m/44'/501'/0'/0'")]
            Truth.assertThat(ed25519DerivedKey?.publicKey?.toHexString())
                .isEqualTo("6CB418F453A8390278DC2AE9CD7FB8F6C4FF888C4DCEA7E40F129690C1D483C4")
        }
    }

}