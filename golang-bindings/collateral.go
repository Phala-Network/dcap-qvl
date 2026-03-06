package dcap

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const httpTimeout = 180 * time.Second

// pcsEndpoints constructs PCCS/PCS API URLs.
type pcsEndpoints struct {
	baseURL string
	tee     string // "sgx" or "tdx"
	fmspc   string
	ca      string
}

func newPcsEndpoints(baseURL string, forSGX bool, fmspc, ca string) pcsEndpoints {
	tee := "tdx"
	if forSGX {
		tee = "sgx"
	}
	base := strings.TrimRight(baseURL, "/")
	base = strings.TrimSuffix(base, "/sgx/certification/v4")
	base = strings.TrimSuffix(base, "/tdx/certification/v4")
	return pcsEndpoints{baseURL: base, tee: tee, fmspc: fmspc, ca: ca}
}

func (e *pcsEndpoints) isPCS() bool {
	return strings.HasPrefix(e.baseURL, IntelPCSURL)
}

func (e *pcsEndpoints) mkURL(tee, path string) string {
	return fmt.Sprintf("%s/%s/certification/v4/%s", e.baseURL, tee, path)
}

func (e *pcsEndpoints) urlPCKCRL() string {
	return e.mkURL("sgx", fmt.Sprintf("pckcrl?ca=%s&encoding=der", e.ca))
}

func (e *pcsEndpoints) urlRootCACRL() string {
	return e.mkURL("sgx", "rootcacrl")
}

func (e *pcsEndpoints) urlTCB() string {
	return e.mkURL(e.tee, fmt.Sprintf("tcb?fmspc=%s", e.fmspc))
}

func (e *pcsEndpoints) urlQEIdentity() string {
	return e.mkURL(e.tee, "qe/identity?update=standard")
}

// getHeader extracts and URL-decodes a response header.
func getHeader(resp *http.Response, name string) (string, error) {
	val := resp.Header.Get(name)
	if val == "" {
		return "", fmt.Errorf("missing header %q", name)
	}
	decoded, err := url.QueryUnescape(val)
	if err != nil {
		return "", fmt.Errorf("failed to decode header %q: %w", name, err)
	}
	return decoded, nil
}

// httpGet performs a GET request and returns the response body.
func httpGet(client *http.Client, reqURL string) ([]byte, error) {
	resp, err := client.Get(reqURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, reqURL)
	}
	return io.ReadAll(resp.Body)
}

// extractCRLURL extracts the CRL Distribution Point URL from a DER certificate.
func extractCRLURL(certDER []byte) (string, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}
	if len(cert.CRLDistributionPoints) > 0 {
		return cert.CRLDistributionPoints[0], nil
	}
	return "", fmt.Errorf("no CRL distribution point found")
}

// extractFMSPCAndCA extracts FMSPC and CA type from a PEM certificate chain.
func extractFMSPCAndCA(pemChain string) (fmspc string, ca string, err error) {
	ext, err := ParsePCKExtensionFromPEM([]byte(pemChain))
	if err != nil {
		return "", "", fmt.Errorf("failed to parse PCK extension: %w", err)
	}
	fmspc = strings.ToUpper(hex.EncodeToString(ext.FMSPC))

	// Determine CA type from issuer of the leaf cert
	block, _ := pem.Decode([]byte(pemChain))
	if block == nil {
		return "", "", fmt.Errorf("failed to decode PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse leaf certificate: %w", err)
	}
	issuer := cert.Issuer.String()
	if strings.Contains(issuer, "Platform") {
		ca = "platform"
	} else {
		ca = "processor"
	}
	return fmspc, ca, nil
}

// parsePEMCerts parses all DER certificates from a PEM chain.
func parsePEMCerts(pemData []byte) [][]byte {
	var certs [][]byte
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certs = append(certs, block.Bytes)
		}
	}
	return certs
}

// tcbInfoResponse matches the JSON structure from PCCS.
type tcbInfoResponse struct {
	TCBInfo   json.RawMessage `json:"tcbInfo"`
	Signature string          `json:"signature"`
}

// qeIdentityResponse matches the JSON structure from PCCS.
type qeIdentityResponse struct {
	EnclaveIdentity json.RawMessage `json:"enclaveIdentity"`
	Signature       string          `json:"signature"`
}

// fetchPCKCertificate fetches a PCK certificate from PCCS using encrypted PPID params.
func fetchPCKCertificate(client *http.Client, pccsURL string, q *Quote) (string, error) {
	qeid := strings.ToUpper(hex.EncodeToString(q.QEID))
	encryptedPPID := strings.ToUpper(hex.EncodeToString(q.EncryptedPPID))
	cpusvn := strings.ToUpper(hex.EncodeToString(q.CertCPUSVN))
	pcesvn := strings.ToUpper(hex.EncodeToString([]byte{byte(*q.CertPCESVN), byte(*q.CertPCESVN >> 8)}))
	pceid := strings.ToUpper(hex.EncodeToString(q.CertPCEID))

	base := strings.TrimRight(pccsURL, "/")
	base = strings.TrimSuffix(base, "/sgx/certification/v4")
	base = strings.TrimSuffix(base, "/tdx/certification/v4")
	reqURL := fmt.Sprintf("%s/sgx/certification/v4/pckcert?qeid=%s&encrypted_ppid=%s&cpusvn=%s&pcesvn=%s&pceid=%s",
		base, qeid, encryptedPPID, cpusvn, pcesvn, pceid)

	resp, err := client.Get(reqURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("failed to fetch PCK certificate from %s: HTTP %d", reqURL, resp.StatusCode)
	}

	// Check SGX-TCBm for TCB level mismatch
	if tcbm := resp.Header.Get("SGX-TCBm"); tcbm != "" {
		tcbmBytes, err := hex.DecodeString(tcbm)
		if err != nil {
			return "", fmt.Errorf("SGX-TCBm header is not valid hex: %w", err)
		}
		if len(tcbmBytes) < 18 {
			return "", fmt.Errorf("SGX-TCBm header too short: expected 18 bytes, got %d", len(tcbmBytes))
		}
		matchedCPUSVN := tcbmBytes[:16]
		matchedPCESVN := uint16(tcbmBytes[16]) | uint16(tcbmBytes[17])<<8

		cpusvnMatch := true
		for i := range matchedCPUSVN {
			if i < len(q.CertCPUSVN) && matchedCPUSVN[i] != q.CertCPUSVN[i] {
				cpusvnMatch = false
				break
			}
		}
		if !cpusvnMatch || matchedPCESVN != *q.CertPCESVN {
			return "", fmt.Errorf(
				"TCB level mismatch: Platform's current TCB (cpusvn=%s, pcesvn=%d) "+
					"is not registered with Intel PCS. Intel matched to a lower TCB level "+
					"(cpusvn=%s, pcesvn=%d). This typically means the platform had a "+
					"microcode/firmware update but MPA registration was not re-run afterward. "+
					"Solution: Run 'mpa_manage -c mpa_registration.conf' on the platform "+
					"to register the new TCB level with Intel.",
				hex.EncodeToString(q.CertCPUSVN), *q.CertPCESVN,
				hex.EncodeToString(matchedCPUSVN), matchedPCESVN,
			)
		}
	}

	pckCertChain, err := getHeader(resp, "SGX-PCK-Certificate-Issuer-Chain")
	if err != nil {
		return "", err
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	pckCert := string(bodyBytes)

	return pckCert + "\n" + pckCertChain, nil
}

// getCollateralForFMSPCImpl fetches collateral from PCCS for a given FMSPC.
func getCollateralForFMSPCImpl(client *http.Client, pccsURL, fmspc, ca string, forSGX bool) (*QuoteCollateralV3, error) {
	endpoints := newPcsEndpoints(pccsURL, forSGX, fmspc, ca)

	// Fetch PCK CRL
	pckCRLResp, err := client.Get(endpoints.urlPCKCRL())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch PCK CRL: %w", err)
	}
	defer pckCRLResp.Body.Close()
	pckCRLIssuerChain, err := getHeader(pckCRLResp, "SGX-PCK-CRL-Issuer-Chain")
	if err != nil {
		return nil, err
	}
	pckCRL, err := io.ReadAll(pckCRLResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read PCK CRL body: %w", err)
	}

	// Fetch TCB Info
	tcbResp, err := client.Get(endpoints.urlTCB())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch TCB info: %w", err)
	}
	defer tcbResp.Body.Close()
	tcbInfoIssuerChain, err := getHeader(tcbResp, "SGX-TCB-Info-Issuer-Chain")
	if err != nil {
		// Fallback header name
		tcbInfoIssuerChain, err = getHeader(tcbResp, "TCB-Info-Issuer-Chain")
		if err != nil {
			return nil, fmt.Errorf("missing TCB info issuer chain header: %w", err)
		}
	}
	rawTCBInfo, err := io.ReadAll(tcbResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCB info body: %w", err)
	}

	// Fetch QE Identity
	qeResp, err := client.Get(endpoints.urlQEIdentity())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch QE identity: %w", err)
	}
	defer qeResp.Body.Close()
	qeIdentityIssuerChain, err := getHeader(qeResp, "SGX-Enclave-Identity-Issuer-Chain")
	if err != nil {
		return nil, err
	}
	rawQEIdentity, err := io.ReadAll(qeResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read QE identity body: %w", err)
	}

	// Fetch Root CA CRL
	var rootCACRL []byte
	if !endpoints.isPCS() {
		body, err := httpGet(client, endpoints.urlRootCACRL())
		if err == nil {
			// PCCS returns hex-encoded CRL instead of binary DER
			decoded, err := hex.DecodeString(string(body))
			if err == nil {
				rootCACRL = decoded
			}
		}
	}
	if rootCACRL == nil {
		// Fallback: extract CRL URL from root certificate in the issuer chain
		certs := parsePEMCerts([]byte(qeIdentityIssuerChain))
		if len(certs) == 0 {
			return nil, fmt.Errorf("no certificates in QE identity issuer chain")
		}
		rootCertDER := certs[len(certs)-1]
		crlURL, err := extractCRLURL(rootCertDER)
		if err != nil {
			return nil, fmt.Errorf("failed to extract CRL URL from root cert: %w", err)
		}
		rootCACRL, err = httpGet(client, crlURL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch root CA CRL from %s: %w", crlURL, err)
		}
	}

	// Parse TCB Info JSON
	var tcbInfoResp tcbInfoResponse
	if err := json.Unmarshal(rawTCBInfo, &tcbInfoResp); err != nil {
		return nil, fmt.Errorf("failed to parse TCB info JSON: %w", err)
	}
	tcbInfoSig, err := hex.DecodeString(tcbInfoResp.Signature)
	if err != nil {
		return nil, fmt.Errorf("TCB info signature is not valid hex: %w", err)
	}

	// Parse QE Identity JSON
	var qeIdentityResp qeIdentityResponse
	if err := json.Unmarshal(rawQEIdentity, &qeIdentityResp); err != nil {
		return nil, fmt.Errorf("failed to parse QE identity JSON: %w", err)
	}
	qeIdentitySig, err := hex.DecodeString(qeIdentityResp.Signature)
	if err != nil {
		return nil, fmt.Errorf("QE identity signature is not valid hex: %w", err)
	}

	return &QuoteCollateralV3{
		PCKCRLIssuerChain:     pckCRLIssuerChain,
		RootCACRL:             rootCACRL,
		PCKCRL:                pckCRL,
		TCBInfoIssuerChain:    tcbInfoIssuerChain,
		TCBInfo:               string(tcbInfoResp.TCBInfo),
		TCBInfoSignature:      tcbInfoSig,
		QEIdentityIssuerChain: qeIdentityIssuerChain,
		QEIdentity:            string(qeIdentityResp.EnclaveIdentity),
		QEIdentitySignature:   qeIdentitySig,
	}, nil
}
