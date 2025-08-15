package com.tangem.hot.sdk.android.crypto

import com.tangem.common.card.EllipticCurve
import com.tangem.crypto.hdWallet.DerivationPath
import com.tangem.crypto.hdWallet.bip32.ExtendedPublicKey
import com.tangem.hot.sdk.android.jni.HDNodeJNI
import com.tangem.hot.sdk.android.jni.TrezorCryptoJNI
import com.tangem.hot.sdk.android.jni.toTrezorCurveName
import com.tangem.hot.sdk.android.model.HDNode
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets

internal object TrezorCryptoFacade {

    fun signMessage(hdNode: HDNodeJNI, message: ByteArray): ByteArray {
        return TrezorCryptoJNI.signMessage(
            hdNodeJNI = hdNode,
            message = message,
        )
    }

    fun masterHdNode(entropy: ByteArray, passphrase: CharArray?, curve: EllipticCurve): HDNode {
        val hdNode = TrezorCryptoJNI.masterHdNode(
            entropy = entropy,
            passphrase = passphrase?.toByteArray() ?: ByteArray(0),
            curveName = curve.toTrezorCurveName(),
        )

        val publicKey = when (curve) {
            EllipticCurve.Ed25519,
            EllipticCurve.Ed25519Slip0010,
            -> hdNode.publicKey.drop(1).toByteArray()
            else -> hdNode.publicKey
        }

        return HDNode(
            publicKey = ExtendedPublicKey(
                publicKey = publicKey,
                chainCode = hdNode.chainCode,
                depth = hdNode.depth,
            ),
            curve = curve,
            hdNodeJNI = hdNode,
        )
    }

    fun deriveHdNode(hdNode: HDNode, derivationPath: DerivationPath): HDNode {
        val derivedHdNode = TrezorCryptoJNI.deriveHdNode(
            hdNodeJNI = requireNotNull(hdNode.hdNodeJNI),
            path = derivationPath.rawPath,
        )

        val publicKey = when (hdNode.curve) {
            EllipticCurve.Ed25519,
            EllipticCurve.Ed25519Slip0010,
            -> derivedHdNode.publicKey.drop(1).toByteArray()
            else -> derivedHdNode.publicKey
        }

        return HDNode(
            publicKey = ExtendedPublicKey(
                publicKey = publicKey,
                chainCode = derivedHdNode.chainCode,
                depth = derivedHdNode.depth,
                parentFingerprint = derivedHdNode.fingerprint(),
                childNumber = derivationPath.nodes.lastIndex.toLong(),
            ),
            curve = hdNode.curve,
            hdNodeJNI = derivedHdNode,
        )
    }

    private fun CharArray.toByteArray(): ByteArray {
        val utf8 = StandardCharsets.UTF_8
        val byteBuffer: ByteBuffer = utf8.encode(CharBuffer.wrap(this))
        val passphraseBytes = ByteArray(byteBuffer.remaining())
        byteBuffer.get(passphraseBytes)
        return passphraseBytes
    }
}