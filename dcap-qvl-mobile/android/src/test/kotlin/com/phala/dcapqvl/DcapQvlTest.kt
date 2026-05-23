package com.phala.dcapqvl

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import java.time.OffsetDateTime
import java.time.format.DateTimeFormatter

/**
 * Local unit tests for the dcap-qvl Android binding.
 *
 * These run on the JVM (no Android device required) — the UniFFI runtime
 * loads `libdcap_qvl_mobile.so` for the host arch via JNA. The build script
 * for these tests copies the host-built .so to `.host-jna/` and the
 * `jna.library.path` system property in `build.gradle.kts` points there.
 */
class DcapQvlTest {
    @Test
    fun parseSgxQuote() {
        val raw = loadResource("sgx_quote")
        val quote = parseQuote(raw)
        assertEquals(QuoteKind.SGX, quote.kind)
        assertEquals(3.toUShort(), quote.header.version)
    }

    @Test
    fun parseTdxQuote() {
        val raw = loadResource("tdx_quote")
        val quote = parseQuote(raw)
        assertEquals(QuoteKind.TDX, quote.kind)
    }

    @Test
    fun verifySgxQuote() {
        val raw = loadResource("sgx_quote")
        val collJson = loadResource("sgx_quote_collateral.json")
        val now = timestampWithinCollateral(collJson)
        val report = verify(raw, collJson, now.toULong())
        assertEquals("ConfigurationAndSWHardeningNeeded", report.status)
        assertEquals(
            TcbStatus.CONFIGURATION_AND_SW_HARDENING_NEEDED,
            report.platformStatus.status
        )
    }

    @Test
    fun verifyTdxQuote() {
        val raw = loadResource("tdx_quote")
        val collJson = loadResource("tdx_quote_collateral.json")
        val now = timestampWithinCollateral(collJson)
        val report = verify(raw, collJson, now.toULong())
        assertFalse(report.status.isEmpty())
    }

    private fun loadResource(name: String): ByteArray {
        val url = javaClass.classLoader!!.getResource(name)
            ?: error("missing fixture: $name (expected under src/test/resources/)")
        return url.openStream().use { it.readBytes() }
    }

    /**
     * Pick a `nowSecs` value that falls inside both the TCB info and QE
     * identity validity windows in the supplied PCCS collateral JSON.
     */
    private fun timestampWithinCollateral(json: ByteArray): Long {
        val root = JSONObject(json.toString(Charsets.UTF_8))
        fun issueAndNext(s: String): Pair<Long, Long> {
            val obj = JSONObject(s)
            val iso = DateTimeFormatter.ISO_DATE_TIME
            val issue = OffsetDateTime.parse(obj.getString("issueDate"), iso)
                .toInstant().epochSecond
            val next = OffsetDateTime.parse(obj.getString("nextUpdate"), iso)
                .toInstant().epochSecond
            return issue to next
        }
        val (ti, tn) = issueAndNext(root.getString("tcb_info"))
        val (qi, qn) = issueAndNext(root.getString("qe_identity"))
        val notBefore = maxOf(ti, qi)
        val notAfter = minOf(tn, qn)
        return notBefore + (notAfter - notBefore) / 2
    }
}
