package network.phala.dcapqvl

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.OffsetDateTime
import java.time.format.DateTimeFormatter
import java.time.ZoneOffset

/**
 * Local unit tests for the dcap-qvl Android binding.
 *
 * These run on the JVM (no Android device required) — the UniFFI runtime
 * loads `libdcap_qvl_mobile.so` for the host arch via JNA. The build script
 * for these tests copies the host-built .so to `src/test/resources/jna/`.
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
        val collJson = loadResource("sgx_quote_collateral.json").toString(Charsets.UTF_8)
        val collateral = parseCollateral(collJson)
        val now = timestampWithinCollateral(collateral)
        val report = verify(raw, collateral, now.toULong())
        assertEquals("ConfigurationAndSWHardeningNeeded", report.status)
        assertEquals(
            TcbStatus.CONFIGURATION_AND_SW_HARDENING_NEEDED,
            report.platformStatus.status
        )
    }

    @Test
    fun verifyTdxQuote() {
        val raw = loadResource("tdx_quote")
        val collJson = loadResource("tdx_quote_collateral.json").toString(Charsets.UTF_8)
        val collateral = parseCollateral(collJson)
        val now = timestampWithinCollateral(collateral)
        val report = verify(raw, collateral, now.toULong())
        assertFalse(report.status.isEmpty())
    }

    private fun loadResource(name: String): ByteArray {
        val url = javaClass.classLoader!!.getResource(name)
            ?: error("missing fixture: $name (expected under src/test/resources/)")
        return url.openStream().use { it.readBytes() }
    }

    /**
     * The PCCS collateral JSON encodes byte fields as hex strings (via
     * `serde-human-bytes` on the Rust side). Decode them back into ByteArray
     * here.
     */
    private fun parseCollateral(json: String): QuoteCollateral {
        val o = JSONObject(json)
        fun hex(key: String): ByteArray {
            val s = o.optString(key, "")
            if (s.isEmpty()) return ByteArray(0)
            require(s.length % 2 == 0) { "$key not hex: odd length" }
            return ByteArray(s.length / 2) { i ->
                Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16).toByte()
            }
        }
        return QuoteCollateral(
            pckCrlIssuerChain = o.getString("pck_crl_issuer_chain"),
            rootCaCrl = hex("root_ca_crl"),
            pckCrl = hex("pck_crl"),
            tcbInfoIssuerChain = o.getString("tcb_info_issuer_chain"),
            tcbInfo = o.getString("tcb_info"),
            tcbInfoSignature = hex("tcb_info_signature"),
            qeIdentityIssuerChain = o.getString("qe_identity_issuer_chain"),
            qeIdentity = o.getString("qe_identity"),
            qeIdentitySignature = hex("qe_identity_signature"),
            pckCertificateChain = o.optString("pck_certificate_chain").ifEmpty { null }
        )
    }

    private fun timestampWithinCollateral(c: QuoteCollateral): Long {
        fun issueAndNext(s: String): Pair<Long, Long> {
            val obj = JSONObject(s)
            val iso = DateTimeFormatter.ISO_DATE_TIME
            val issue = OffsetDateTime.parse(obj.getString("issueDate"), iso)
                .toInstant().epochSecond
            val next = OffsetDateTime.parse(obj.getString("nextUpdate"), iso)
                .toInstant().epochSecond
            return issue to next
        }
        val (ti, tn) = issueAndNext(c.tcbInfo)
        val (qi, qn) = issueAndNext(c.qeIdentity)
        val notBefore = maxOf(ti, qi)
        val notAfter = minOf(tn, qn)
        return notBefore + (notAfter - notBefore) / 2
    }
}
