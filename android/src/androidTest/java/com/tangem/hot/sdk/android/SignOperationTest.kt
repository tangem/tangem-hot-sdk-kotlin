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
                        curve = EllipticCurve.Ed25519Slip0010,
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
                .isEqualTo("13B7D460DEAFC87C60619A16032DD110F33568968433C22B8633942310E8B5AE620922D8C1D01FCC25B99208C2B4FEB859FA990CD733DEA0BCCB4AA36D44320F")
            Truth.assertThat(signature4.toHexString())
                .isEqualTo("4D03D794689B8568418584938C62B6804AC988F8FAAD92EBFE102BF108540DE1A236E0762A099C119576DDB9D93164D28B9104EF734D28BEF49642761AE9A10E")
        }
    }
}