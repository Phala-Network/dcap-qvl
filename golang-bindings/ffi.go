package dcap

/*
#cgo linux,amd64  LDFLAGS: -Wl,-Bstatic -ldcap_qvl -Wl,-Bdynamic -lm -ldl -lpthread
#cgo linux,arm64  LDFLAGS: -Wl,-Bstatic -ldcap_qvl -Wl,-Bdynamic -lm -ldl -lpthread
#cgo darwin,amd64 LDFLAGS: -ldcap_qvl -framework Security -framework CoreFoundation
#cgo darwin,arm64 LDFLAGS: -ldcap_qvl -framework Security -framework CoreFoundation
#include "dcap_qvl.h"
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"fmt"
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

	urlBytes := []byte(pccsURL)

	var outJSON *C.char
	var outLen C.size_t

	rc := C.dcap_get_collateral(
		(*C.char)(unsafe.Pointer(&urlBytes[0])),
		C.size_t(len(urlBytes)),
		(*C.uint8_t)(unsafe.Pointer(&rawQuote[0])),
		C.size_t(len(rawQuote)),
		&outJSON,
		&outLen,
	)

	data, err := ffiResult(rc, outJSON, outLen)
	if err != nil {
		return nil, err
	}

	var coll QuoteCollateralV3
	if err := json.Unmarshal(data, &coll); err != nil {
		return nil, fmt.Errorf("dcap: failed to unmarshal collateral: %w", err)
	}
	return &coll, nil
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

	urlBytes := []byte(pccsURL)
	fmspcBytes := []byte(fmspc)
	caBytes := []byte(ca)

	isSGXInt := C.int(0)
	if isSGX {
		isSGXInt = C.int(1)
	}

	var outJSON *C.char
	var outLen C.size_t

	rc := C.dcap_get_collateral_for_fmspc(
		(*C.char)(unsafe.Pointer(&urlBytes[0])),
		C.size_t(len(urlBytes)),
		(*C.char)(unsafe.Pointer(&fmspcBytes[0])),
		C.size_t(len(fmspcBytes)),
		(*C.char)(unsafe.Pointer(&caBytes[0])),
		C.size_t(len(caBytes)),
		isSGXInt,
		&outJSON,
		&outLen,
	)

	data, err := ffiResult(rc, outJSON, outLen)
	if err != nil {
		return nil, err
	}

	var coll QuoteCollateralV3
	if err := json.Unmarshal(data, &coll); err != nil {
		return nil, fmt.Errorf("dcap: failed to unmarshal collateral: %w", err)
	}
	return &coll, nil
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
