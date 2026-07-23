package com.tangem.hot.sdk.android.jni

import com.tangem.common.card.EllipticCurve

internal fun EllipticCurve.toTrezorCurveName(): String {
    return when (this) {
        EllipticCurve.Ed25519 -> "ed25519 cardano seed"
        EllipticCurve.Ed25519Slip0010 -> "ed25519"
        EllipticCurve.Secp256k1 -> "secp256k1"
        // unsupported
        EllipticCurve.Secp256r1,
        EllipticCurve.Bls12381G2,
        EllipticCurve.Bls12381G2Aug,
        EllipticCurve.Bls12381G2Pop,
        EllipticCurve.Bip0340,
        -> error("$this is not supported")
    }
}