package com.phala.dcapqvl

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import java.time.OffsetDateTime
import java.time.format.DateTimeFormatter

/**
 * On-device instrumented test.
 *
 * Unlike the local JVM unit tests (which point JNA at a host `.so` via
 * `jna.library.path`), this runs on an Android emulator and exercises the
 * real path a consumer hits: JNA extracts `libdcap_qvl_mobile.so` from the
 * packaged jniLibs for the device ABI and loads it. This is the closest
 * automated proxy for "an app depends on the AAR and calls verify()".
 *
 * Fixtures are read from the androidTest APK's assets, staged there by
 * `scripts/build_android.sh`.
 */
@RunWith(AndroidJUnit4::class)
class DcapQvlInstrumentedTest {
    @Test
    fun parseSgxQuoteOnDevice() {
        val quote = parseQuote(asset("sgx_quote"))
        assertEquals(QuoteKind.SGX, quote.kind)
        assertEquals(3.toUShort(), quote.header.version)
    }

    @Test
    fun verifySgxQuoteOnDevice() {
        val raw = asset("sgx_quote")
        val collJson = asset("sgx_quote_collateral.json")
        val now = timestampWithinCollateral(collJson)
        val report = verify(raw, collJson, now.toULong())
        assertEquals("ConfigurationAndSWHardeningNeeded", report.status)
        assertEquals(
            TcbStatus.CONFIGURATION_AND_SW_HARDENING_NEEDED,
            report.platformStatus.status
        )
    }

    @Test
    fun verifyTdxQuoteOnDevice() {
        val raw = asset("tdx_quote")
        val collJson = asset("tdx_quote_collateral.json")
        val now = timestampWithinCollateral(collJson)
        val report = verify(raw, collJson, now.toULong())
        assertFalse(report.status.isEmpty())
    }

    private fun asset(name: String): ByteArray {
        val ctx = InstrumentationRegistry.getInstrumentation().context
        return ctx.assets.open(name).use { it.readBytes() }
    }

    private fun timestampWithinCollateral(json: ByteArray): Long {
        val root = JSONObject(json.toString(Charsets.UTF_8))
        fun issueAndNext(s: String): Pair<Long, Long> {
            val obj = JSONObject(s)
            val iso = DateTimeFormatter.ISO_DATE_TIME
            val issue = OffsetDateTime.parse(obj.getString("issueDate"), iso).toInstant().epochSecond
            val next = OffsetDateTime.parse(obj.getString("nextUpdate"), iso).toInstant().epochSecond
            return issue to next
        }
        val (ti, tn) = issueAndNext(root.getString("tcb_info"))
        val (qi, qn) = issueAndNext(root.getString("qe_identity"))
        val notBefore = maxOf(ti, qi)
        val notAfter = minOf(tn, qn)
        return notBefore + (notAfter - notBefore) / 2
    }
}
