package dcap

/*
#cgo linux,amd64  LDFLAGS: -Wl,-Bstatic -ldcap_qvl -Wl,-Bdynamic -lm -ldl -lpthread
#cgo linux,arm64  LDFLAGS: -Wl,-Bstatic -ldcap_qvl -Wl,-Bdynamic -lm -ldl -lpthread
#cgo darwin,amd64 LDFLAGS: -ldcap_qvl
#cgo darwin,arm64 LDFLAGS: -ldcap_qvl
#include "dcap_qvl.h"
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"unsafe"
)

// ffiCall invokes an FFI function and returns the JSON output string.
// It handles memory management: the returned JSON is copied to Go memory
// and the Rust-allocated buffer is freed.
func ffiResult(rc C.int, outJSON *C.char, outLen C.size_t) ([]byte, error) {
	if outJSON == nil {
		return nil, fmt.Errorf("dcap ffi: nil output")
	}
	goBytes := C.GoBytes(unsafe.Pointer(outJSON), C.int(outLen))
	C.dcap_free((*C.char)(unsafe.Pointer(outJSON)), outLen)

	if rc != 0 {
		return nil, fmt.Errorf("dcap ffi: %s", string(goBytes))
	}
	return goBytes, nil
}

// ParseQuote parses a raw SGX/TDX quote binary.
func ParseQuote(rawQuote []byte) (*Quote, error) {
	if len(rawQuote) == 0 {
		return nil, fmt.Errorf("dcap: empty quote input")
	}

	var outJSON *C.char
	var outLen C.size_t

	rc := C.dcap_parse_quote(
		(*C.uint8_t)(unsafe.Pointer(&rawQuote[0])),
		C.size_t(len(rawQuote)),
		&outJSON,
		&outLen,
	)

	data, err := ffiResult(rc, outJSON, outLen)
	if err != nil {
		return nil, err
	}

	var quote Quote
	if err := json.Unmarshal(data, &quote); err != nil {
		return nil, fmt.Errorf("dcap: failed to unmarshal quote JSON: %w", err)
	}
	return &quote, nil
}

// Verify verifies a quote against collateral using Intel's production root CA.
func Verify(rawQuote []byte, collateral *QuoteCollateralV3, nowSecs uint64) (*VerifiedReport, error) {
	if len(rawQuote) == 0 {
		return nil, fmt.Errorf("dcap: empty quote input")
	}

	collJSON, err := json.Marshal(collateral)
	if err != nil {
		return nil, fmt.Errorf("dcap: failed to marshal collateral: %w", err)
	}

	var outJSON *C.char
	var outLen C.size_t

	rc := C.dcap_verify(
		(*C.uint8_t)(unsafe.Pointer(&rawQuote[0])),
		C.size_t(len(rawQuote)),
		(*C.char)(unsafe.Pointer(&collJSON[0])),
		C.size_t(len(collJSON)),
		C.uint64_t(nowSecs),
		&outJSON,
		&outLen,
	)

	data, err := ffiResult(rc, outJSON, outLen)
	if err != nil {
		return nil, err
	}

	var report VerifiedReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("dcap: failed to unmarshal verify result: %w", err)
	}
	return &report, nil
}

// VerifyWithRootCA verifies a quote with a custom root CA (DER-encoded).
func VerifyWithRootCA(rawQuote []byte, collateral *QuoteCollateralV3, rootCADer []byte, nowSecs uint64) (*VerifiedReport, error) {
	if len(rawQuote) == 0 {
		return nil, fmt.Errorf("dcap: empty quote input")
	}
	if len(rootCADer) == 0 {
		return nil, fmt.Errorf("dcap: empty root CA input")
	}

	collJSON, err := json.Marshal(collateral)
	if err != nil {
		return nil, fmt.Errorf("dcap: failed to marshal collateral: %w", err)
	}

	var outJSON *C.char
	var outLen C.size_t

	rc := C.dcap_verify_with_root_ca(
		(*C.uint8_t)(unsafe.Pointer(&rawQuote[0])),
		C.size_t(len(rawQuote)),
		(*C.char)(unsafe.Pointer(&collJSON[0])),
		C.size_t(len(collJSON)),
		(*C.uint8_t)(unsafe.Pointer(&rootCADer[0])),
		C.size_t(len(rootCADer)),
		C.uint64_t(nowSecs),
		&outJSON,
		&outLen,
	)

	data, err := ffiResult(rc, outJSON, outLen)
	if err != nil {
		return nil, err
	}

	var report VerifiedReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("dcap: failed to unmarshal verify result: %w", err)
	}
	return &report, nil
}

// GetCollateral fetches collateral from a PCCS server for a given quote.
func GetCollateral(pccsURL string, rawQuote []byte) (*QuoteCollateralV3, error) {
	if pccsURL == "" {
		return nil, fmt.Errorf("dcap: empty PCCS URL input")
	}
	if len(rawQuote) == 0 {
		return nil, fmt.Errorf("dcap: empty quote input")
	}

	q, err := ParseQuote(rawQuote)
	if err != nil {
		return nil, fmt.Errorf("dcap: failed to parse quote: %w", err)
	}

	client := &http.Client{Timeout: httpTimeout}

	// Get PCK certificate chain
	var pckChain string
	switch {
	case q.CertType == 5:
		// cert_type 5: PCK cert chain is embedded in the quote
		pckChain = q.CertChainPEM
	case q.CertType == 2 || q.CertType == 3:
		// cert_type 2/3: fetch PCK cert from PCCS using encrypted PPID
		if q.CertPCESVN == nil {
			return nil, fmt.Errorf("dcap: cert_type %d but missing encrypted PPID params", q.CertType)
		}
		pckChain, err = fetchPCKCertificate(client, pccsURL, q)
		if err != nil {
			return nil, fmt.Errorf("dcap: failed to fetch PCK certificate: %w", err)
		}
	default:
		return nil, fmt.Errorf("dcap: unsupported cert_type %d", q.CertType)
	}

	// Extract FMSPC and CA from the PCK certificate chain
	fmspc, ca, err := extractFMSPCAndCA(pckChain)
	if err != nil {
		return nil, fmt.Errorf("dcap: failed to extract FMSPC/CA: %w", err)
	}

	isSGX := q.QuoteType == "SGX"
	coll, err := getCollateralForFMSPCImpl(client, pccsURL, fmspc, ca, isSGX)
	if err != nil {
		return nil, err
	}

	// Attach the PCK certificate chain for offline verification
	coll.PCKCertificateChain = pckChain
	return coll, nil
}

// GetCollateralForFMSPC fetches collateral for a known FMSPC and CA type.
func GetCollateralForFMSPC(pccsURL, fmspc, ca string, isSGX bool) (*QuoteCollateralV3, error) {
	if pccsURL == "" {
		return nil, fmt.Errorf("dcap: empty PCCS URL input")
	}
	if fmspc == "" {
		return nil, fmt.Errorf("dcap: empty FMSPC input")
	}
	if ca == "" {
		return nil, fmt.Errorf("dcap: empty CA input")
	}

	client := &http.Client{Timeout: httpTimeout}
	return getCollateralForFMSPCImpl(client, pccsURL, fmspc, ca, isSGX)
}

// GetCollateralAndVerify fetches collateral and verifies in one call.
func GetCollateralAndVerify(rawQuote []byte, pccsURL string) (*VerifiedReport, error) {
	coll, err := GetCollateral(pccsURL, rawQuote)
	if err != nil {
		return nil, err
	}

	// Parse quote to check if it has a PCK certificate chain
	q, err := ParseQuote(rawQuote)
	if err != nil {
		return nil, err
	}

	// If the quote has an embedded cert chain, attach it to collateral
	if q.CertChainPEM != "" && coll.PCKCertificateChain == "" {
		coll.PCKCertificateChain = q.CertChainPEM
	}

	nowSecs := uint64(time.Now().Unix())
	return Verify(rawQuote, coll, nowSecs)
}

// ParsePCKExtensionFromPEM parses Intel SGX extension from a PEM certificate chain.
func ParsePCKExtensionFromPEM(pemBytes []byte) (*PCKExtension, error) {
	if len(pemBytes) == 0 {
		return nil, fmt.Errorf("dcap: empty PEM input")
	}

	var outJSON *C.char
	var outLen C.size_t

	rc := C.dcap_parse_pck_extension_from_pem(
		(*C.uint8_t)(unsafe.Pointer(&pemBytes[0])),
		C.size_t(len(pemBytes)),
		&outJSON,
		&outLen,
	)

	data, err := ffiResult(rc, outJSON, outLen)
	if err != nil {
		return nil, err
	}

	var ext PCKExtension
	if err := json.Unmarshal(data, &ext); err != nil {
		return nil, fmt.Errorf("dcap: failed to unmarshal PCK extension: %w", err)
	}
	return &ext, nil
}
