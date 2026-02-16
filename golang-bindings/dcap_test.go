package dcap

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	sampleOnce        sync.Once
	sgxQuote          []byte
	tdxQuote          []byte
	sgxCollateralJSON []byte
	tdxCollateralJSON []byte
)

func sampleDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "sample")
}

func loadSamples(t *testing.T) {
	t.Helper()
	sampleOnce.Do(func() {
		dir := sampleDir()
		var err error
		sgxQuote, err = os.ReadFile(filepath.Join(dir, "sgx_quote"))
		if err != nil {
			t.Fatalf("read sgx_quote: %v", err)
		}
		tdxQuote, err = os.ReadFile(filepath.Join(dir, "tdx_quote"))
		if err != nil {
			t.Fatalf("read tdx_quote: %v", err)
		}
		sgxCollateralJSON, err = os.ReadFile(filepath.Join(dir, "sgx_quote_collateral.json"))
		if err != nil {
			t.Fatalf("read sgx_quote_collateral.json: %v", err)
		}
		tdxCollateralJSON, err = os.ReadFile(filepath.Join(dir, "tdx_quote_collateral.json"))
		if err != nil {
			t.Fatalf("read tdx_quote_collateral.json: %v", err)
		}
	})
}

// nowFromCollateral computes a valid timestamp within the collateral's validity window.
// Ported from tests/verify_quote.rs.
func nowFromCollateral(t *testing.T, coll *QuoteCollateralV3) uint64 {
	t.Helper()

	parseIssueNext := func(jsonStr string) (uint64, uint64) {
		var obj struct {
			IssueDate  string `json:"issueDate"`
			NextUpdate string `json:"nextUpdate"`
		}
		if err := json.Unmarshal([]byte(jsonStr), &obj); err != nil {
			t.Fatalf("parse JSON dates: %v", err)
		}
		issue, err := time.Parse(time.RFC3339, obj.IssueDate)
		if err != nil {
			t.Fatalf("parse issueDate: %v", err)
		}
		next, err := time.Parse(time.RFC3339, obj.NextUpdate)
		if err != nil {
			t.Fatalf("parse nextUpdate: %v", err)
		}
		return uint64(issue.Unix()), uint64(next.Unix())
	}

	parseCRLBounds := func(crlDER []byte) (uint64, *uint64) {
		crl, err := x509.ParseRevocationList(crlDER)
		if err != nil {
			t.Fatalf("parse CRL: %v", err)
		}
		thisUpdate := uint64(crl.ThisUpdate.Unix())
		if !crl.NextUpdate.IsZero() {
			nu := uint64(crl.NextUpdate.Unix())
			return thisUpdate, &nu
		}
		return thisUpdate, nil
	}

	tcbIssue, tcbNext := parseIssueNext(coll.TCBInfo)
	qeIssue, qeNext := parseIssueNext(coll.QEIdentity)

	notBefore := tcbIssue
	if qeIssue > notBefore {
		notBefore = qeIssue
	}
	notAfter := tcbNext
	if qeNext < notAfter {
		notAfter = qeNext
	}

	for _, crlDER := range [][]byte{coll.RootCACRL, coll.PCKCRL} {
		thisUpdate, nextUpdate := parseCRLBounds(crlDER)
		if thisUpdate > notBefore {
			notBefore = thisUpdate
		}
		if nextUpdate != nil && *nextUpdate < notAfter {
			notAfter = *nextUpdate
		}
	}

	if notBefore > notAfter {
		t.Fatal("collateral validity window invalid")
	}
	if notAfter > notBefore {
		return notAfter - 1
	}
	return notAfter
}

func loadCollateral(t *testing.T, data []byte) *QuoteCollateralV3 {
	t.Helper()
	var coll QuoteCollateralV3
	if err := json.Unmarshal(data, &coll); err != nil {
		t.Fatalf("unmarshal collateral: %v", err)
	}
	return &coll
}

func extractPEMCertDERs(t *testing.T, chainPEM string) [][]byte {
	t.Helper()

	var certDERs [][]byte
	rest := []byte(chainPEM)
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		certDERs = append(certDERs, block.Bytes)
	}
	if len(certDERs) == 0 {
		t.Fatal("no certificates found in PEM chain")
	}
	return certDERs
}

// --- Quote Parsing Tests ---

func TestParseQuoteSGX(t *testing.T) {
	loadSamples(t)
	q, err := ParseQuote(sgxQuote)
	if err != nil {
		t.Fatalf("ParseQuote(sgx): %v", err)
	}

	// Header fields from snapshot
	if q.Header.Version != 3 {
		t.Errorf("version = %d, want 3", q.Header.Version)
	}
	if q.Header.AttestationKeyType != 2 {
		t.Errorf("attestation_key_type = %d, want 2", q.Header.AttestationKeyType)
	}
	if q.Header.TeeType != 0 {
		t.Errorf("tee_type = %d, want 0", q.Header.TeeType)
	}
	if q.Header.QESVN != 10 {
		t.Errorf("qe_svn = %d, want 10", q.Header.QESVN)
	}
	if q.Header.PCESVN != 15 {
		t.Errorf("pce_svn = %d, want 15", q.Header.PCESVN)
	}

	// Report type must be SGX
	if q.Report.Type != "SGX" {
		t.Errorf("report type = %q, want SGX", q.Report.Type)
	}

	// SGX-specific fields must be present
	if len(q.Report.MrEnclave) == 0 {
		t.Error("mr_enclave is empty")
	}
	if len(q.Report.MrSigner) == 0 {
		t.Error("mr_signer is empty")
	}
	if len(q.Report.CPUSVN) == 0 {
		t.Error("cpu_svn is empty")
	}
	if len(q.Report.ReportData) == 0 {
		t.Error("report_data is empty")
	}
	if q.Report.MiscSelect == nil {
		t.Error("misc_select is nil")
	}
	if q.Report.ISVProdID == nil {
		t.Error("isv_prod_id is nil")
	}
	if q.Report.ISVSVN == nil {
		t.Error("isv_svn is nil")
	}

	// cpu_svn from snapshot: [11, 11, 26, 24, 255, 255, 4, 0, ...]
	expectedCPUSVN := "0b0b1a18ffff04000000000000000000"
	if hex.EncodeToString(q.Report.CPUSVN) != expectedCPUSVN {
		t.Errorf("cpu_svn = %s, want %s", hex.EncodeToString(q.Report.CPUSVN), expectedCPUSVN)
	}
}

func TestParseQuoteTDX(t *testing.T) {
	loadSamples(t)
	q, err := ParseQuote(tdxQuote)
	if err != nil {
		t.Fatalf("ParseQuote(tdx): %v", err)
	}

	// Header fields from snapshot
	if q.Header.Version != 4 {
		t.Errorf("version = %d, want 4", q.Header.Version)
	}
	if q.Header.AttestationKeyType != 2 {
		t.Errorf("attestation_key_type = %d, want 2", q.Header.AttestationKeyType)
	}
	if q.Header.TeeType != 0x81 {
		t.Errorf("tee_type = %d, want 0x81", q.Header.TeeType)
	}

	// Report type must be TD10
	if q.Report.Type != "TD10" {
		t.Errorf("report type = %q, want TD10", q.Report.Type)
	}

	// TDX-specific fields must be present
	if len(q.Report.MrTD) == 0 {
		t.Error("mr_td is empty")
	}
	if len(q.Report.RTMR0) == 0 {
		t.Error("rt_mr0 is empty")
	}
	if len(q.Report.RTMR1) == 0 {
		t.Error("rt_mr1 is empty")
	}
	if len(q.Report.RTMR2) == 0 {
		t.Error("rt_mr2 is empty")
	}
	if len(q.Report.RTMR3) == 0 {
		t.Error("rt_mr3 is empty")
	}
	if len(q.Report.TeeTCBSVN) == 0 {
		t.Error("tee_tcb_svn is empty")
	}
	if len(q.Report.ReportData) == 0 {
		t.Error("report_data is empty")
	}
}

func TestParseQuoteCertChain(t *testing.T) {
	loadSamples(t)
	for _, tc := range []struct {
		name  string
		quote []byte
	}{
		{"SGX", sgxQuote},
		{"TDX", tdxQuote},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, err := ParseQuote(tc.quote)
			if err != nil {
				t.Fatalf("ParseQuote: %v", err)
			}
			if q.CertChainPEM == "" {
				t.Error("cert_chain_pem is empty")
			}
			if !strings.HasPrefix(q.CertChainPEM, "-----BEGIN CERTIFICATE-----") {
				t.Error("cert_chain_pem doesn't start with PEM header")
			}
		})
	}
}

func TestParseQuoteFMSPC(t *testing.T) {
	loadSamples(t)
	for _, tc := range []struct {
		name  string
		quote []byte
	}{
		{"SGX", sgxQuote},
		{"TDX", tdxQuote},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, err := ParseQuote(tc.quote)
			if err != nil {
				t.Fatalf("ParseQuote: %v", err)
			}
			if q.FMSPC == "" {
				t.Error("fmspc is empty")
			}
		})
	}
}

func TestParseQuoteCA(t *testing.T) {
	loadSamples(t)
	for _, tc := range []struct {
		name  string
		quote []byte
	}{
		{"SGX", sgxQuote},
		{"TDX", tdxQuote},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, err := ParseQuote(tc.quote)
			if err != nil {
				t.Fatalf("ParseQuote: %v", err)
			}
			if q.CA != "processor" && q.CA != "platform" {
				t.Errorf("ca = %q, want processor or platform", q.CA)
			}
		})
	}
}

func TestParseQuoteType(t *testing.T) {
	loadSamples(t)
	sgx, err := ParseQuote(sgxQuote)
	if err != nil {
		t.Fatalf("ParseQuote(sgx): %v", err)
	}
	if sgx.QuoteType != "SGX" {
		t.Errorf("sgx quote_type = %q, want SGX", sgx.QuoteType)
	}

	tdx, err := ParseQuote(tdxQuote)
	if err != nil {
		t.Fatalf("ParseQuote(tdx): %v", err)
	}
	if tdx.QuoteType != "TDX" {
		t.Errorf("tdx quote_type = %q, want TDX", tdx.QuoteType)
	}
}

func TestParseQuoteInvalidInput(t *testing.T) {
	_, err := ParseQuote([]byte{0, 1, 2, 3})
	if err == nil {
		t.Error("expected error for invalid quote")
	}

	_, err = ParseQuote([]byte{})
	if err == nil {
		t.Error("expected error for empty quote")
	}
}

func TestVerifyEmptyQuoteInput(t *testing.T) {
	_, err := Verify(nil, &QuoteCollateralV3{}, 0)
	if err == nil {
		t.Error("expected error for empty quote input")
	}
}

func TestVerifyWithRootCAEmptyInput(t *testing.T) {
	_, err := VerifyWithRootCA(nil, &QuoteCollateralV3{}, []byte{1, 2, 3}, 0)
	if err == nil {
		t.Error("expected error for empty quote input")
	}

	_, err = VerifyWithRootCA([]byte{1, 2, 3}, &QuoteCollateralV3{}, nil, 0)
	if err == nil {
		t.Error("expected error for empty root CA input")
	}
}

func TestGetCollateralEmptyInput(t *testing.T) {
	_, err := GetCollateral("", []byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for empty PCCS URL input")
	}

	_, err = GetCollateral(PhalaPCCSURL, nil)
	if err == nil {
		t.Error("expected error for empty quote input")
	}
}

func TestGetCollateralForFMSPCEmptyInput(t *testing.T) {
	_, err := GetCollateralForFMSPC("", "001122334455", "processor", true)
	if err == nil {
		t.Error("expected error for empty PCCS URL input")
	}

	_, err = GetCollateralForFMSPC(PhalaPCCSURL, "", "processor", true)
	if err == nil {
		t.Error("expected error for empty FMSPC input")
	}

	_, err = GetCollateralForFMSPC(PhalaPCCSURL, "001122334455", "", true)
	if err == nil {
		t.Error("expected error for empty CA input")
	}
}

// --- Verification Tests ---

func TestVerifySGXQuote(t *testing.T) {
	loadSamples(t)
	coll := loadCollateral(t, sgxCollateralJSON)
	now := nowFromCollateral(t, coll)

	report, err := Verify(sgxQuote, coll, now)
	if err != nil {
		t.Fatalf("Verify(sgx): %v", err)
	}

	if report.Status != "ConfigurationAndSWHardeningNeeded" {
		t.Errorf("status = %q, want ConfigurationAndSWHardeningNeeded", report.Status)
	}
	expectedAdvisory := []string{"INTEL-SA-00289", "INTEL-SA-00615"}
	if len(report.AdvisoryIDs) != len(expectedAdvisory) {
		t.Fatalf("advisory_ids len = %d, want %d", len(report.AdvisoryIDs), len(expectedAdvisory))
	}
	for i, id := range expectedAdvisory {
		if report.AdvisoryIDs[i] != id {
			t.Errorf("advisory_ids[%d] = %q, want %q", i, report.AdvisoryIDs[i], id)
		}
	}
}

func TestVerifyTDXQuote(t *testing.T) {
	loadSamples(t)
	coll := loadCollateral(t, tdxCollateralJSON)
	now := nowFromCollateral(t, coll)

	report, err := Verify(tdxQuote, coll, now)
	if err != nil {
		t.Fatalf("Verify(tdx): %v", err)
	}

	if report.Status != "UpToDate" {
		t.Errorf("status = %q, want UpToDate", report.Status)
	}
	if len(report.AdvisoryIDs) != 0 {
		t.Errorf("advisory_ids = %v, want empty", report.AdvisoryIDs)
	}
}

func TestVerifyWithRootCASGXQuote(t *testing.T) {
	loadSamples(t)
	coll := loadCollateral(t, sgxCollateralJSON)
	now := nowFromCollateral(t, coll)

	q, err := ParseQuote(sgxQuote)
	if err != nil {
		t.Fatalf("ParseQuote(sgx): %v", err)
	}
	if q.CertChainPEM == "" {
		t.Fatal("missing cert chain in SGX quote")
	}
	certDERs := extractPEMCertDERs(t, q.CertChainPEM)
	rootDER := certDERs[len(certDERs)-1]

	report, err := VerifyWithRootCA(sgxQuote, coll, rootDER, now)
	if err != nil {
		t.Fatalf("VerifyWithRootCA(sgx): %v", err)
	}

	if report.Status != "ConfigurationAndSWHardeningNeeded" {
		t.Errorf("status = %q, want ConfigurationAndSWHardeningNeeded", report.Status)
	}
	expectedAdvisory := []string{"INTEL-SA-00289", "INTEL-SA-00615"}
	if len(report.AdvisoryIDs) != len(expectedAdvisory) {
		t.Fatalf("advisory_ids len = %d, want %d", len(report.AdvisoryIDs), len(expectedAdvisory))
	}
	for i, id := range expectedAdvisory {
		if report.AdvisoryIDs[i] != id {
			t.Errorf("advisory_ids[%d] = %q, want %q", i, report.AdvisoryIDs[i], id)
		}
	}
}

func TestVerifyWithRootCATDXQuote(t *testing.T) {
	loadSamples(t)
	coll := loadCollateral(t, tdxCollateralJSON)
	now := nowFromCollateral(t, coll)

	q, err := ParseQuote(tdxQuote)
	if err != nil {
		t.Fatalf("ParseQuote(tdx): %v", err)
	}
	if q.CertChainPEM == "" {
		t.Fatal("missing cert chain in TDX quote")
	}
	certDERs := extractPEMCertDERs(t, q.CertChainPEM)
	rootDER := certDERs[len(certDERs)-1]

	report, err := VerifyWithRootCA(tdxQuote, coll, rootDER, now)
	if err != nil {
		t.Fatalf("VerifyWithRootCA(tdx): %v", err)
	}

	if report.Status != "UpToDate" {
		t.Errorf("status = %q, want UpToDate", report.Status)
	}
	if len(report.AdvisoryIDs) != 0 {
		t.Errorf("advisory_ids = %v, want empty", report.AdvisoryIDs)
	}
}

func TestVerifyFullReport(t *testing.T) {
	loadSamples(t)
	coll := loadCollateral(t, sgxCollateralJSON)
	now := nowFromCollateral(t, coll)

	report, err := Verify(sgxQuote, coll, now)
	if err != nil {
		t.Fatalf("Verify(sgx): %v", err)
	}

	// Report fields must be populated
	if report.Report.Type == "" {
		t.Error("report.type is empty")
	}
	if len(report.Report.ReportData) == 0 {
		t.Error("report.report_data is empty")
	}

	// QEStatus and PlatformStatus must have valid TcbStatus
	validStatuses := map[TcbStatus]bool{
		TcbStatusUpToDate:                          true,
		TcbStatusOutOfDate:                         true,
		TcbStatusOutOfDateConfigurationNeeded:      true,
		TcbStatusConfigurationNeeded:               true,
		TcbStatusSWHardeningNeeded:                 true,
		TcbStatusConfigurationAndSWHardeningNeeded: true,
		TcbStatusRevoked:                           true,
	}
	if !validStatuses[report.QEStatus.Status] {
		t.Errorf("qe_status.status = %q, not a valid TcbStatus", report.QEStatus.Status)
	}
	if !validStatuses[report.PlatformStatus.Status] {
		t.Errorf("platform_status.status = %q, not a valid TcbStatus", report.PlatformStatus.Status)
	}
}

func TestVerifyInvalidQuote(t *testing.T) {
	loadSamples(t)
	coll := loadCollateral(t, sgxCollateralJSON)
	_, err := Verify([]byte{0, 1, 2, 3}, coll, 1000000)
	if err == nil {
		t.Error("expected error for invalid quote verification")
	}
}

// --- PCK Extension Tests ---

func TestPCKExtensionFromQuote(t *testing.T) {
	loadSamples(t)
	for _, tc := range []struct {
		name  string
		quote []byte
	}{
		{"SGX", sgxQuote},
		{"TDX", tdxQuote},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, err := ParseQuote(tc.quote)
			if err != nil {
				t.Fatalf("ParseQuote: %v", err)
			}
			if q.CertChainPEM == "" {
				t.Skip("no cert chain in quote")
			}

			ext, err := ParsePCKExtensionFromPEM([]byte(q.CertChainPEM))
			if err != nil {
				t.Fatalf("ParsePCKExtensionFromPEM: %v", err)
			}

			// FMSPC from extension should match quote (case-insensitive hex)
			if !strings.EqualFold(hex.EncodeToString(ext.FMSPC), q.FMSPC) {
				t.Errorf("fmspc mismatch: ext=%s, quote=%s",
					hex.EncodeToString(ext.FMSPC), q.FMSPC)
			}
			if len(ext.PPID) == 0 {
				t.Error("ppid is empty")
			}
		})
	}
}

func TestPCKExtensionFromPEM(t *testing.T) {
	loadSamples(t)
	q, err := ParseQuote(sgxQuote)
	if err != nil {
		t.Fatalf("ParseQuote: %v", err)
	}
	if q.CertChainPEM == "" {
		t.Skip("no cert chain")
	}

	ext, err := ParsePCKExtensionFromPEM([]byte(q.CertChainPEM))
	if err != nil {
		t.Fatalf("ParsePCKExtensionFromPEM: %v", err)
	}

	// All expected fields should be populated
	if len(ext.PPID) == 0 {
		t.Error("ppid empty")
	}
	if len(ext.CPUSVN) == 0 {
		t.Error("cpu_svn empty")
	}
	if len(ext.FMSPC) == 0 {
		t.Error("fmspc empty")
	}
	if len(ext.PCEID) == 0 {
		t.Error("pce_id empty")
	}
	if len(ext.RawExtension) == 0 {
		t.Error("raw_extension empty")
	}
}

func TestPCKExtensionGetValue(t *testing.T) {
	loadSamples(t)
	q, err := ParseQuote(sgxQuote)
	if err != nil {
		t.Fatalf("ParseQuote: %v", err)
	}

	ext, err := ParsePCKExtensionFromPEM([]byte(q.CertChainPEM))
	if err != nil {
		t.Fatalf("ParsePCKExtensionFromPEM: %v", err)
	}

	// PPID
	ppid, err := ext.GetValue("1.2.840.113741.1.13.1.1")
	if err != nil {
		t.Fatalf("GetValue(PPID): %v", err)
	}
	if !bytesEqual(ppid, ext.PPID) {
		t.Errorf("PPID mismatch: GetValue=%x, field=%x", ppid, ext.PPID)
	}

	// FMSPC
	fmspc, err := ext.GetValue("1.2.840.113741.1.13.1.4")
	if err != nil {
		t.Fatalf("GetValue(FMSPC): %v", err)
	}
	if !bytesEqual(fmspc, ext.FMSPC) {
		t.Errorf("FMSPC mismatch: GetValue=%x, field=%x", fmspc, ext.FMSPC)
	}

	// PCEID
	pceid, err := ext.GetValue("1.2.840.113741.1.13.1.3")
	if err != nil {
		t.Fatalf("GetValue(PCEID): %v", err)
	}
	if !bytesEqual(pceid, ext.PCEID) {
		t.Errorf("PCEID mismatch: GetValue=%x, field=%x", pceid, ext.PCEID)
	}

	// CPUSVN (nested under TCB: 1.2.840.113741.1.13.1.2.18)
	cpusvn, err := ext.GetValue("1.2.840.113741.1.13.1.2.18")
	if err != nil {
		t.Fatalf("GetValue(CPUSVN): %v", err)
	}
	if !bytesEqual(cpusvn, ext.CPUSVN) {
		t.Errorf("CPUSVN mismatch: GetValue=%x, field=%x", cpusvn, ext.CPUSVN)
	}

	// PCESVN (nested under TCB: 1.2.840.113741.1.13.1.2.17)
	pcesvn, err := ext.GetValue("1.2.840.113741.1.13.1.2.17")
	if err != nil {
		t.Fatalf("GetValue(PCESVN): %v", err)
	}
	if pcesvn == nil {
		t.Fatal("GetValue(PCESVN) returned nil")
	}
}

func TestPCKExtensionMissingOID(t *testing.T) {
	loadSamples(t)
	q, err := ParseQuote(sgxQuote)
	if err != nil {
		t.Fatalf("ParseQuote: %v", err)
	}

	ext, err := ParsePCKExtensionFromPEM([]byte(q.CertChainPEM))
	if err != nil {
		t.Fatalf("ParsePCKExtensionFromPEM: %v", err)
	}

	val, err := ext.GetValue("1.2.840.113741.1.13.1.99")
	if err != nil {
		t.Fatalf("GetValue(missing): %v", err)
	}
	if val != nil {
		t.Errorf("expected nil for missing OID, got %x", val)
	}
}

func TestPCKExtensionInvalidOID(t *testing.T) {
	loadSamples(t)
	q, err := ParseQuote(sgxQuote)
	if err != nil {
		t.Fatalf("ParseQuote: %v", err)
	}

	ext, err := ParsePCKExtensionFromPEM([]byte(q.CertChainPEM))
	if err != nil {
		t.Fatalf("ParsePCKExtensionFromPEM: %v", err)
	}

	_, err = ext.GetValue("not.a.valid.oid")
	if err == nil {
		t.Error("expected error for invalid OID")
	}
}

func TestPCKExtensionBadPEM(t *testing.T) {
	_, err := ParsePCKExtensionFromPEM([]byte("not a valid PEM"))
	if err == nil {
		t.Error("expected error for bad PEM input")
	}
}

func TestPCKExtensionEmptyPEM(t *testing.T) {
	_, err := ParsePCKExtensionFromPEM(nil)
	if err == nil {
		t.Error("expected error for empty PEM input")
	}
}

// --- Collateral JSON Tests ---

func TestCollateralJSONRoundtrip(t *testing.T) {
	loadSamples(t)
	coll := loadCollateral(t, sgxCollateralJSON)

	// Marshal back to JSON
	encoded, err := json.Marshal(coll)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Unmarshal again
	var coll2 QuoteCollateralV3
	if err := json.Unmarshal(encoded, &coll2); err != nil {
		t.Fatalf("Unmarshal roundtrip: %v", err)
	}

	// Verify key fields preserved
	if coll2.TCBInfo != coll.TCBInfo {
		t.Error("tcb_info not preserved")
	}
	if coll2.QEIdentity != coll.QEIdentity {
		t.Error("qe_identity not preserved")
	}
	if hex.EncodeToString(coll2.RootCACRL) != hex.EncodeToString(coll.RootCACRL) {
		t.Error("root_ca_crl not preserved")
	}
	if hex.EncodeToString(coll2.PCKCRL) != hex.EncodeToString(coll.PCKCRL) {
		t.Error("pck_crl not preserved")
	}
	if coll2.PCKCRLIssuerChain != coll.PCKCRLIssuerChain {
		t.Error("pck_crl_issuer_chain not preserved")
	}
}

func TestHexBytesEncoding(t *testing.T) {
	// Marshal
	h := HexBytes{0xde, 0xad, 0xbe, 0xef}
	data, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(data) != `"deadbeef"` {
		t.Errorf("marshal = %s, want %q", data, "deadbeef")
	}

	// Unmarshal
	var h2 HexBytes
	if err := json.Unmarshal([]byte(`"cafebabe"`), &h2); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if hex.EncodeToString(h2) != "cafebabe" {
		t.Errorf("unmarshal = %x, want cafebabe", h2)
	}

	// Empty string
	var h3 HexBytes
	if err := json.Unmarshal([]byte(`""`), &h3); err != nil {
		t.Fatalf("Unmarshal empty: %v", err)
	}
	if h3 != nil {
		t.Errorf("empty unmarshal = %x, want nil", h3)
	}

	// Nil marshal
	var h4 HexBytes
	data, err = json.Marshal(h4)
	if err != nil {
		t.Fatalf("Marshal nil: %v", err)
	}
	if string(data) != `""` {
		t.Errorf("nil marshal = %s, want empty string", data)
	}
}
