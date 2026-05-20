import XCTest
@testable import DcapQvl

private extension Data {
    init?(hexString: String) {
        let len = hexString.count
        guard len.isMultiple(of: 2) else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(len / 2)
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
}

final class DcapQvlTests: XCTestCase {
    func testParseSgxQuote() throws {
        let raw = try loadResource("sgx_quote")
        let quote = try parseQuote(rawQuote: raw)
        XCTAssertEqual(quote.kind, .sgx)
        XCTAssertEqual(quote.header.version, 3)
    }

    func testParseTdxQuote() throws {
        let raw = try loadResource("tdx_quote")
        let quote = try parseQuote(rawQuote: raw)
        XCTAssertEqual(quote.kind, .tdx)
    }

    func testVerifySgxQuote() throws {
        let raw = try loadResource("sgx_quote")
        let collateralJSON = try loadResource("sgx_quote_collateral.json")
        let (collateral, now) = try Self.parseCollateral(collateralJSON)
        let report = try verify(rawQuote: raw, collateral: collateral, nowSecs: now)
        XCTAssertEqual(report.status, "ConfigurationAndSWHardeningNeeded")
        XCTAssertEqual(
            report.platformStatus.status,
            TcbStatus.configurationAndSwHardeningNeeded
        )
    }

    func testVerifyTdxQuote() throws {
        let raw = try loadResource("tdx_quote")
        let collateralJSON = try loadResource("tdx_quote_collateral.json")
        let (collateral, now) = try Self.parseCollateral(collateralJSON)
        let report = try verify(rawQuote: raw, collateral: collateral, nowSecs: now)
        XCTAssertFalse(report.status.isEmpty)
    }

    // MARK: - Helpers

    private func loadResource(_ name: String) throws -> Data {
        guard let url = Bundle.module.url(forResource: name, withExtension: nil) else {
            throw NSError(domain: "DcapQvlTests", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "missing fixture: \(name)"])
        }
        return try Data(contentsOf: url)
    }

    private static func parseCollateral(_ raw: Data) throws -> (QuoteCollateral, UInt64) {
        // The PCCS collateral JSON returned by `tests/verify_quote.rs` matches
        // our QuoteCollateral struct field-for-field (snake_case). We use the
        // bog-standard JSONSerialization rather than introducing a Codable
        // dependency for this small surface.
        let root = try JSONSerialization.jsonObject(with: raw) as? [String: Any] ?? [:]

        // Byte fields are serialized as hex strings by `serde-human-bytes` on
        // the Rust side; decode them back to Data here.
        func bytes(_ key: String) -> Data {
            guard let hex = root[key] as? String else { return Data() }
            return Data(hexString: hex) ?? Data()
        }
        func str(_ key: String) -> String { (root[key] as? String) ?? "" }

        let collateral = QuoteCollateral(
            pckCrlIssuerChain: str("pck_crl_issuer_chain"),
            rootCaCrl: bytes("root_ca_crl"),
            pckCrl: bytes("pck_crl"),
            tcbInfoIssuerChain: str("tcb_info_issuer_chain"),
            tcbInfo: str("tcb_info"),
            tcbInfoSignature: bytes("tcb_info_signature"),
            qeIdentityIssuerChain: str("qe_identity_issuer_chain"),
            qeIdentity: str("qe_identity"),
            qeIdentitySignature: bytes("qe_identity_signature"),
            pckCertificateChain: root["pck_certificate_chain"] as? String
        )

        let now = try Self.timestampWithinCollateral(collateral)
        return (collateral, now)
    }

    private static func timestampWithinCollateral(_ c: QuoteCollateral) throws -> UInt64 {
        func issueAndNext(_ json: String) throws -> (UInt64, UInt64) {
            guard let data = json.data(using: .utf8),
                  let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let issue = obj["issueDate"] as? String,
                  let next = obj["nextUpdate"] as? String
            else { throw NSError(domain: "DcapQvlTests", code: 2) }
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            let alt = ISO8601DateFormatter()
            alt.formatOptions = [.withInternetDateTime]
            let issueDate = formatter.date(from: issue) ?? alt.date(from: issue)
            let nextDate = formatter.date(from: next) ?? alt.date(from: next)
            return (UInt64(issueDate!.timeIntervalSince1970),
                    UInt64(nextDate!.timeIntervalSince1970))
        }
        let (ti, tn) = try issueAndNext(c.tcbInfo)
        let (qi, qn) = try issueAndNext(c.qeIdentity)
        let notBefore = max(ti, qi)
        let notAfter = min(tn, qn)
        return notBefore + (notAfter - notBefore) / 2
    }
}
