package com.tangem.hot.sdk.android

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth
import com.tangem.common.extensions.calculateSha256
import com.tangem.hot.sdk.TangemHotSdk
import com.tangem.hot.sdk.model.HotAuth
import com.tangem.hot.sdk.model.MnemonicType
import com.tangem.hot.sdk.model.UnlockHotWallet
import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.math.abs
import kotlin.math.ln
import kotlin.math.pow
import kotlin.math.sqrt
import kotlin.time.Duration.Companion.minutes

private const val TEST_COUNT = 300
private const val BINS = 16           // small χ² buckets (fast)
private const val ALPHA = 0.001       // strict enough for small N

@RunWith(AndroidJUnit4::class)
class MnemonicRandomnessTests {

    private fun generatePhrases(
        count: Int, nWords: MnemonicType = MnemonicType.Words12
    ): List<String> {
        val activity = ActivityScenario.launch(MainActivity::class.java)
        val out = mutableListOf<String>()
        activity.onActivity { act ->
            val sdk = TangemHotSdk.create(act)
            runTest(timeout = 10.minutes) {
                repeat(count) {
                    val walletId = sdk.generateWallet(auth = HotAuth.NoAuth, mnemonicType = nWords)
                    val priv = sdk.exportMnemonic(UnlockHotWallet(walletId, HotAuth.NoAuth))
                    out += priv.mnemonic.mnemonicComponents.joinToString(" ")
                }
            }
        }
        return out
    }

    private fun chiSquareUniformP(counts: IntArray): Double {
        val n = counts.sum().toDouble()
        val k = counts.size
        val exp = n / k
        var chi2 = 0.0
        for (c in counts) {
            val d = c - exp
            chi2 += d * d / exp
        }
        // Wilson–Hilferty normal approx to get upper-tail p
        val kf = (k - 1).toDouble()
        val z = ((chi2 / kf).pow(1.0 / 3.0) - (1 - 2.0 / (9.0 * kf))) / sqrt(2.0 / (9.0 * kf))
        return 1.0 - 0.5 * (1 + erf(z / sqrt(2.0)))
    }

    private fun erf(x: Double): Double {
        val sign = if (x < 0) -1 else 1
        val a1 = 0.254829592
        val a2 = -0.284496736
        val a3 = 1.421413741
        val a4 = -1.453152027
        val a5 = 1.061405429
        val p = 0.3275911
        val t = 1.0 / (1.0 + p * abs(x))
        val y = 1.0 - (((((a5 * t + a4) * t + a3) * t + a2) * t + a1) * t) * kotlin.math.exp(-x * x)
        return sign * y
    }

    private fun BooleanArray.monobitP(): Double {
        var sum = 0
        for (b in this) sum += if (b) 1 else -1
        val sObs = abs(sum) / sqrt(size.toDouble())
        val x = sObs / sqrt(2.0)
        val erfc = 1.0 - erf(x)
        return erfc
    }

    private fun runsP(bits: BooleanArray): Double {
        val n = bits.size
        val pi = bits.count { it }.toDouble() / n
        if (abs(pi - 0.5) >= 2.0 / sqrt(n.toDouble())) return 0.0
        var v = 1
        for (i in 1 until n) if (bits[i] != bits[i - 1]) v++
        val num = abs(v - 2.0 * n * pi * (1 - pi))
        val den = 2.0 * sqrt(2.0 * n.toDouble()) * pi * (1 - pi)
        val x = num / den
        return 1.0 - erf(x)  // erfc(x) = 1 - erf(x)
    }

    private fun ByteArray.toBits(): BooleanArray {
        val out = BooleanArray(size * 8)
        var i = 0
        for (b in this) for (k in 7 downTo 0) out[i++] = ((b.toInt() ushr k) and 1) == 1
        return out
    }

    @Test
    fun no_duplicates_in_small_batch() {
        MnemonicType.entries.forEach { type ->
            val phrases = generatePhrases(TEST_COUNT, type)
            Truth.assertThat(phrases.toSet().size).isEqualTo(phrases.size)
        }
    }

    @Test
    fun first_word_uniformity_fast_chi_square() {
        MnemonicType.entries.forEach { type ->
            val phrases = generatePhrases(TEST_COUNT, type)
            val counts = IntArray(BINS)
            for (p in phrases) {
                val first = p.substringBefore(' ')
                val h = first.calculateSha256()
                val bucket =
                    (h[0].toInt() and 0xFF) ushr (8 - (ln(BINS.toDouble()) / ln(2.0)).toInt())
                counts[bucket]++
            }
            val p = chiSquareUniformP(counts)
            // reject if extremely unlikely uniform (too structured) or extremely likely (suspiciously perfect)
            Truth.assertThat(p).isGreaterThan(ALPHA)
            Truth.assertThat(p).isLessThan(1 - ALPHA)
        }
    }

    @Test
    fun hash_bits_pass_monobit_and_runs_fast() {
        MnemonicType.entries.forEach { type ->
            val phrases = generatePhrases(TEST_COUNT, type)
            // concatenate SHA-256 of each phrase for ~SAMPLE_N*256 bits
            val bits =
                phrases.flatMap { it.calculateSha256().toBits().asIterable() }.toBooleanArray()

            val pMono = bits.monobitP()
            val pRuns = runsP(bits)

            Truth.assertThat(pMono).isGreaterThan(ALPHA)
            Truth.assertThat(pRuns).isGreaterThan(ALPHA)
        }
    }

    @Test
    fun low_serial_correlation_fast() {
        MnemonicType.entries.forEach { type ->
            val phrases = generatePhrases(TEST_COUNT, type)
            // turn phrase into a 64-bit value via hash
            val xs = phrases.map {
                val h = it.calculateSha256()
                var v = 0L
                for (i in 0 until 8) v = (v shl 8) or (h[i].toLong() and 0xFF)
                v.toDouble()
            }
            var sx = 0.0
            var sy = 0.0
            var sxx = 0.0
            var syy = 0.0
            var sxy = 0.0
            val n = xs.size - 1
            for (i in 0 until n) {
                val x = xs[i];
                val y = xs[i + 1]
                sx += x; sy += y; sxx += x * x; syy += y * y; sxy += x * y
            }
            val cov = (sxy - (sx * sy) / n) / n
            val varX = (sxx - (sx * sx) / n) / n
            val varY = (syy - (sy * sy) / n) / n
            val corr = cov / sqrt(varX * varY)
            Truth.assertThat(abs(corr)).isLessThan(0.1)  // loose bound for small N
        }
    }
}