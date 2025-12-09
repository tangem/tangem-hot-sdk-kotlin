package com.tangem.hot.sdk.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth
import com.tangem.common.card.EllipticCurve
import com.tangem.common.extensions.calculateSha256
import com.tangem.common.extensions.hexToBytes
import com.tangem.common.extensions.toHexString
import com.tangem.crypto.hdWallet.DerivationPath
import com.tangem.hot.sdk.model.DataToSign
import com.tangem.hot.sdk.model.HotAuth
import com.tangem.hot.sdk.model.UnlockHotWallet
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SignOperationTest {

    @Test
    fun signOperation() {
        withPreparedSdk { walletId, hotSdk ->
            val dataToSign = "Hello, Tangem!".toByteArray()
            val derivationPath = "m/44'/60'/0'/0/0"
            val signResult = hotSdk.signHashes(
                unlockHotWallet = UnlockHotWallet(
                    walletId = walletId,
                    auth = HotAuth.NoAuth
                ),
                dataToSign = listOf(
                    DataToSign(
                        curve = EllipticCurve.Secp256k1,
                        derivationPath = DerivationPath(derivationPath),
                        hashes = listOf(dataToSign)
                    )
                )
            )

            val signature = signResult.first().signatures.first()

            Truth.assertThat(
                signature.size
            ).isEqualTo(64)
        }
    }

    @Test
    fun signOperationBls() {
        withPreparedSdk { walletId, hotSdk ->
            val dataToSign =
                "A3A6136282A97B09CAE57DFAD492B78EAE685E2D55E3279D18B41CB11D2B0260EF6E5B2AE15E98956B0C4E652F86714203FFF9EFA7FED9D3ACF053FE697EE4D832B21484A711EB70989E2720FD262E8AD3E474909E7098DABD33870EF5DBC13A".hexToBytes()
            val signResult = hotSdk.signHashes(
                unlockHotWallet = UnlockHotWallet(
                    walletId = walletId,
                    auth = HotAuth.NoAuth
                ),
                dataToSign = listOf(
                    DataToSign(
                        curve = EllipticCurve.Bls12381G2,
                        derivationPath = null,
                        hashes = listOf(dataToSign)
                    )
                )
            )
            val signature = signResult.first().signatures.first()
            Truth.assertThat(
                signature.toHexString()
            ).isEqualTo(
                "A9C4B6D2C1111D050BB611CB055A32A77B60BF7EE08EB6592DD8971152B166495AFBD49728C1F3A2ECE1921C82F0932C0BB65002F8284FA6E475C16191601C2A8868FD4F3FA8C4E18021BDF174BA4EA25B1E787EE480E35B4CADFDEDD942010A"
            )
        }
    }

    @Test
    fun signOperation_ed25519() {
        withPreparedSdk { walletId, hotSdk ->
            val dataToSign = "Hello, Tangem!".toByteArray()
            val derivationPath = "m/44'/501'/0'/0'"
            val signResult = hotSdk.signHashes(
                unlockHotWallet = UnlockHotWallet(
                    walletId = walletId,
                    auth = HotAuth.NoAuth
                ),
                dataToSign = listOf(
                    DataToSign(
                        curve = EllipticCurve.Ed25519Slip0010,
                        derivationPath = DerivationPath(derivationPath),
                        hashes = listOf(dataToSign.calculateSha256())
                    )
                )
            )

            val signature = signResult.first().signatures.first()

            Truth.assertThat(
                signature.toHexString()
            ).isEqualTo(
                "FA1B5C4821833FD6FB16D8F6A28C08CD05D059F01789F10B107485E150A52906820E9588C9E03C1A91E3ACC7BA35B10D0E91632D0000903A377A2399318BD403"
            )
        }
    }

    @Test
    fun signOperation_ed25519_cardano() {
        withPreparedSdk { walletId, hotSdk ->
            val dataToSign = "Hello, Tangem!".toByteArray()
            val derivationPath = "m/1852'/1815'/0'/0/0"
            val signResult = hotSdk.signHashes(
                unlockHotWallet = UnlockHotWallet(
                    walletId = walletId,
                    auth = HotAuth.NoAuth
                ),
                dataToSign = listOf(
                    DataToSign(
                        curve = EllipticCurve.Ed25519,
                        derivationPath = DerivationPath(derivationPath),
                        hashes = listOf(dataToSign.calculateSha256())
                    )
                )
            )
            val signature = signResult.first().signatures.first()
            Truth.assertThat(
                signature.toHexString()
            ).isEqualTo(
                "2B3163A7DC64B8CD773560494692C36185627C66C3DE80538877E203010719E082373001C37FF37D14E401DC15E77025E698109818E7E85AA5D7E9DB32253E09"
            )
        }
    }

    @Test
    fun signOperation_multipleHashes() {
        withPreparedSdk { walletId, hotSdk ->
            val dataToSign1 = "Hello, Tangem!".toByteArray()
            val dataToSign2 = "Hello, World!".toByteArray()
            val derivationPath = "m/44'/60'/0'/0/0"
            val signResult = hotSdk.signHashes(
                unlockHotWallet = UnlockHotWallet(
                    walletId = walletId,
                    auth = HotAuth.NoAuth
                ),
                dataToSign = listOf(
                    DataToSign(
                        curve = EllipticCurve.Secp256k1,
                        derivationPath = DerivationPath(derivationPath),
                        hashes = listOf(dataToSign1, dataToSign2)
                    ),
                    DataToSign(
                        curve = EllipticCurve.Ed25519,
                        derivationPath = DerivationPath(derivationPath),
                        hashes = listOf(dataToSign1, dataToSign2)
                    )
                )
            )
            val signature1 = signResult.first().signatures[0]
            val signature2 = signResult.first().signatures[1]
            Truth.assertThat(signature1).isNotEqualTo(signature2)
            Truth.assertThat(signature1.size).isEqualTo(64)
            Truth.assertThat(signature2.size).isEqualTo(64)

            val signature3 = signResult[1].signatures[0]
            val signature4 = signResult[1].signatures[1]

            Truth.assertThat(signature3).isNotEqualTo(signature4)
            Truth.assertThat(signature3.toHexString())
                .isEqualTo("3FDB7B252F51343A35EEAE3FB0B81ECCFD3DE3E021B1B578A103BA7AE5C59E65D7AF54701ACC9B56EF6F0451B1B6E68BA0F7E2F3FC7D1CD1FE9248251CCE910F")
            Truth.assertThat(signature4.toHexString())
                .isEqualTo("C098B9A94F139AFC564EA8E6A33B39B3B24FD8FAD33EEEE4CCB4929A2BE6664815D8CE3FA4A3D4DCA6989226D9BD755F88D78A248BC6113C325E74A4B074D90C")
        }
    }
}