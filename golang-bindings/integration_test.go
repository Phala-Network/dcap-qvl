//go:build integration

package dcap

import (
	"testing"
)

func TestGetCollateral(t *testing.T) {
	loadSamples(t)

	coll, err := GetCollateral(PhalaPCCSURL, sgxQuote)
	if err != nil {
		t.Fatalf("GetCollateral: %v", err)
	}

	if coll.TCBInfo == "" {
		t.Error("tcb_info is empty")
	}
	if coll.QEIdentity == "" {
		t.Error("qe_identity is empty")
	}
	if len(coll.RootCACRL) == 0 {
		t.Error("root_ca_crl is empty")
	}
	if len(coll.PCKCRL) == 0 {
		t.Error("pck_crl is empty")
	}
	if coll.PCKCRLIssuerChain == "" {
		t.Error("pck_crl_issuer_chain is empty")
	}
}

func TestGetCollateralForFMSPC(t *testing.T) {
	loadSamples(t)

	q, err := ParseQuote(sgxQuote)
	if err != nil {
		t.Fatalf("ParseQuote: %v", err)
	}

	coll, err := GetCollateralForFMSPC(PhalaPCCSURL, q.FMSPC, q.CA, q.QuoteType == "SGX")
	if err != nil {
		t.Fatalf("GetCollateralForFMSPC: %v", err)
	}

	if coll.TCBInfo == "" {
		t.Error("tcb_info is empty")
	}
	if coll.QEIdentity == "" {
		t.Error("qe_identity is empty")
	}
}

func TestGetCollateralForFMSPCTDX(t *testing.T) {
	loadSamples(t)

	q, err := ParseQuote(tdxQuote)
	if err != nil {
		t.Fatalf("ParseQuote: %v", err)
	}

	coll, err := GetCollateralForFMSPC(PhalaPCCSURL, q.FMSPC, q.CA, q.QuoteType == "SGX")
	if err != nil {
		t.Fatalf("GetCollateralForFMSPC: %v", err)
	}

	if coll.TCBInfo == "" {
		t.Error("tcb_info is empty")
	}
	if coll.QEIdentity == "" {
		t.Error("qe_identity is empty")
	}
}

func TestGetCollateralAndVerify(t *testing.T) {
	loadSamples(t)

	report, err := GetCollateralAndVerify(sgxQuote, PhalaPCCSURL)
	if err != nil {
		t.Fatalf("GetCollateralAndVerify: %v", err)
	}

	if report.Status == "" {
		t.Error("status is empty")
	}
	if report.Report.Type == "" {
		t.Error("report.type is empty")
	}
}
