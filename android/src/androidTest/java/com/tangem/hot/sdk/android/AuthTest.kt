package com.tangem.hot.sdk.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth
import com.tangem.common.card.EllipticCurve
import com.tangem.common.extensions.hexToBytes
import com.tangem.hot.sdk.exception.WrongPasswordException
import com.tangem.hot.sdk.model.DeriveWalletRequest
import com.tangem.hot.sdk.model.HotAuth
import com.tangem.hot.sdk.model.UnlockHotWallet
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AuthTest {

    @Test
    fun authSmoke() {
        withPreparedSdk { walletId, sdk ->
            val password = "1234".toCharArray()

            val newWalletId = sdk.changeAuth(
                unlockHotWallet = UnlockHotWallet(walletId, auth = HotAuth.NoAuth),
                auth = HotAuth.Password(password)
            )

            val result = sdk.derivePublicKey(
                unlockHotWallet = UnlockHotWallet(
                    walletId = newWalletId,
                    HotAuth.Password(password)
                ),
                request = DeriveWalletRequest(
                    requests = listOf(
                        DeriveWalletRequest.Request(
                            curve = EllipticCurve.Bls12381G2,
                            paths = emptyList()
                        )
                    )
                )
            )

            val seedKey = result.responses.first().seedKey.publicKey
            Truth.assertThat(seedKey)
                .isEqualTo("96FE65B72234DD76D5E8B0585C5FC6D4651E85FA1086CD4E9290F1303176606A430BD32B5106F49F461C022F75E37ADE".hexToBytes())
        }
    }


    @Test
    fun authWrongWalletIdAuth() {
        withPreparedSdk { walletId, sdk ->
            val password = "1234".toCharArray()

            sdk.changeAuth(
                unlockHotWallet = UnlockHotWallet(walletId, auth = HotAuth.NoAuth),
                auth = HotAuth.Password(password)
            )

            val result = runCatching {
                sdk.derivePublicKey(
                    unlockHotWallet = UnlockHotWallet(
                        walletId = walletId,
                        HotAuth.Password(password)
                    ),
                    request = DeriveWalletRequest(
                        requests = listOf(
                            DeriveWalletRequest.Request(
                                curve = EllipticCurve.Bls12381G2,
                                paths = emptyList()
                            )
                        )
                    )
                )
            }.onFailure {
                Truth.assertThat(it).isInstanceOf(IllegalArgumentException::class.java)
            }.onSuccess {
                error("Should return error")
            }
        }
    }

    @Test
    fun authWrongPassword() {
        withPreparedSdk { walletId, sdk ->
            val password = "1234".toCharArray()
            val wrongPassword = "5678".toCharArray()

            val newWalletId = sdk.changeAuth(
                unlockHotWallet = UnlockHotWallet(walletId, auth = HotAuth.NoAuth),
                auth = HotAuth.Password(password)
            )

            runCatching {
                sdk.derivePublicKey(
                    unlockHotWallet = UnlockHotWallet(
                        walletId = newWalletId,
                        auth = HotAuth.Password(wrongPassword)
                    ),
                    request = DeriveWalletRequest(
                        requests = listOf(
                            DeriveWalletRequest.Request(
                                curve = EllipticCurve.Bls12381G2,
                                paths = emptyList()
                            )
                        )
                    )
                )
            }.onFailure {
                Truth.assertThat(it).isInstanceOf(WrongPasswordException::class.java)
            }.onSuccess {
                error("Should return error")
            }
        }
    }

    @Test
    fun authChangePassword() {
        withPreparedSdk { walletId, sdk ->
            val password = "1234".toCharArray()
            val changePassword = "5678".toCharArray()

            val newWalletId = sdk.changeAuth(
                unlockHotWallet = UnlockHotWallet(walletId, auth = HotAuth.NoAuth),
                auth = HotAuth.Password(password)
            )

            val newWalletId2 = sdk.changeAuth(
                unlockHotWallet = UnlockHotWallet(newWalletId, auth = HotAuth.Password(password)),
                auth = HotAuth.Password(changePassword)
            )

            val result = sdk.derivePublicKey(
                unlockHotWallet = UnlockHotWallet(
                    walletId = newWalletId2,
                    auth = HotAuth.Password(changePassword)
                ),
                request = DeriveWalletRequest(
                    requests = listOf(
                        DeriveWalletRequest.Request(
                            curve = EllipticCurve.Bls12381G2,
                            paths = emptyList()
                        )
                    )
                )
            )

            val seedKey = result.responses.first().seedKey.publicKey
            Truth.assertThat(seedKey)
                .isEqualTo("96FE65B72234DD76D5E8B0585C5FC6D4651E85FA1086CD4E9290F1303176606A430BD32B5106F49F461C022F75E37ADE".hexToBytes())
        }
    }

    @Test
    fun authRemovePassword() {
        withPreparedSdk { walletId, sdk ->
            val password = "1234".toCharArray()

            val newWalletId = sdk.changeAuth(
                unlockHotWallet = UnlockHotWallet(walletId, auth = HotAuth.NoAuth),
                auth = HotAuth.Password(password)
            )

            val newWalletId2 = sdk.changeAuth(
                unlockHotWallet = UnlockHotWallet(newWalletId, auth = HotAuth.Password(password)),
                auth = HotAuth.NoAuth
            )

            val result = sdk.derivePublicKey(
                unlockHotWallet = UnlockHotWallet(
                    walletId = newWalletId2,
                    auth = HotAuth.NoAuth
                ),
                request = DeriveWalletRequest(
                    requests = listOf(
                        DeriveWalletRequest.Request(
                            curve = EllipticCurve.Bls12381G2,
                            paths = emptyList()
                        )
                    )
                )
            )

            val seedKey = result.responses.first().seedKey.publicKey
            Truth.assertThat(seedKey)
                .isEqualTo("96FE65B72234DD76D5E8B0585C5FC6D4651E85FA1086CD4E9290F1303176606A430BD32B5106F49F461C022F75E37ADE".hexToBytes())
        }
    }

    // Biometry tests are not possible at the moment due to the AndroidJUnit4 runner not supporting it.
}