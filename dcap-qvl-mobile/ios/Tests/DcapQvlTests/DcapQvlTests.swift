import XCTest
@testable import DcapQvl

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
        let now = try Self.timestampWithinCollateral(collateralJSON)
        let report = try verify(rawQuote: raw, collateralJson: collateralJSON, nowSecs: now)
        XCTAssertEqual(report.status, "ConfigurationAndSWHardeningNeeded")
        XCTAssertEqual(
            report.platformStatus.status,
            TcbStatus.configurationAndSwHardeningNeeded
        )
    }

    func testVerifyTdxQuote() throws {
        let raw = try loadResource("tdx_quote")
        let collateralJSON = try loadResource("tdx_quote_collateral.json")
        let now = try Self.timestampWithinCollateral(collateralJSON)
        let report = try verify(rawQuote: raw, collateralJson: collateralJSON, nowSecs: now)
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

    /// Pick a `nowSecs` value that falls inside both the TCB info and QE
    /// identity validity windows in the supplied PCCS collateral JSON.
    private static func timestampWithinCollateral(_ data: Data) throws -> UInt64 {
        let root = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        func issueAndNext(_ jsonString: String) throws -> (UInt64, UInt64) {
            let obj = try JSONSerialization.jsonObject(
                with: jsonString.data(using: .utf8)!
            ) as! [String: Any]
            let issue = obj["issueDate"] as! String
            let next = obj["nextUpdate"] as! String
            let primary = ISO8601DateFormatter()
            primary.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            let fallback = ISO8601DateFormatter()
            fallback.formatOptions = [.withInternetDateTime]
            let issueDate = primary.date(from: issue) ?? fallback.date(from: issue)!
            let nextDate = primary.date(from: next) ?? fallback.date(from: next)!
            return (UInt64(issueDate.timeIntervalSince1970),
                    UInt64(nextDate.timeIntervalSince1970))
        }
        let (ti, tn) = try issueAndNext(root["tcb_info"] as! String)
        let (qi, qn) = try issueAndNext(root["qe_identity"] as! String)
        let notBefore = max(ti, qi)
        let notAfter = min(tn, qn)
        return notBefore + (notAfter - notBefore) / 2
    }
}
