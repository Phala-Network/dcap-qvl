package dcap

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// HexBytes is a []byte that JSON-encodes as a hex string.
// Matches Rust's serde-human-bytes serialization format.
type HexBytes []byte

func (h HexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(h))
}

func (h *HexBytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		*h = nil
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("HexBytes: invalid hex: %w", err)
	}
	*h = b
	return nil
}

// Quote represents a parsed SGX/TDX quote.
type Quote struct {
	Header       QuoteHeader `json:"header"`
	Report       QuoteReport `json:"report"`
	CertType     uint16      `json:"cert_type"`
	CertChainPEM string      `json:"cert_chain_pem,omitempty"`
	FMSPC        string      `json:"fmspc,omitempty"`
	CA           string      `json:"ca,omitempty"`
	QuoteType    string      `json:"quote_type"`
	// cert_type 2/3: encrypted PPID params for PCK cert fetch
	QEID         HexBytes `json:"qe_id,omitempty"`
	EncryptedPPID HexBytes `json:"encrypted_ppid,omitempty"`
	CertCPUSVN   HexBytes `json:"cert_cpusvn,omitempty"`
	CertPCESVN   *uint16  `json:"cert_pcesvn,omitempty"`
	CertPCEID    HexBytes `json:"cert_pceid,omitempty"`
}

// QuoteHeader is the quote header.
type QuoteHeader struct {
	Version            uint16   `json:"version"`
	AttestationKeyType uint16   `json:"attestation_key_type"`
	TeeType            uint32   `json:"tee_type"`
	QESVN              uint16   `json:"qe_svn"`
	PCESVN             uint16   `json:"pce_svn"`
	QEVendorID         HexBytes `json:"qe_vendor_id"`
	UserData           HexBytes `json:"user_data"`
}

// QuoteReport is a flattened report from either SGX EnclaveReport, TD10, or TD15.
type QuoteReport struct {
	Type       string   `json:"type"`
	ReportData HexBytes `json:"report_data"`
	// TDX fields (TD10 and TD15)
	TeeTCBSVN      HexBytes `json:"tee_tcb_svn,omitempty"`
	MrSeam         HexBytes `json:"mr_seam,omitempty"`
	MrSignerSeam   HexBytes `json:"mr_signer_seam,omitempty"`
	SeamAttributes HexBytes `json:"seam_attributes,omitempty"`
	TdAttributes   HexBytes `json:"td_attributes,omitempty"`
	XFAM           HexBytes `json:"xfam,omitempty"`
	MrTD           HexBytes `json:"mr_td,omitempty"`
	MrConfigID     HexBytes `json:"mr_config_id,omitempty"`
	MrOwner        HexBytes `json:"mr_owner,omitempty"`
	MrOwnerConfig  HexBytes `json:"mr_owner_config,omitempty"`
	RTMR0          HexBytes `json:"rt_mr0,omitempty"`
	RTMR1          HexBytes `json:"rt_mr1,omitempty"`
	RTMR2          HexBytes `json:"rt_mr2,omitempty"`
	RTMR3          HexBytes `json:"rt_mr3,omitempty"`
	// TD15 extra fields
	TeeTCBSVN2  HexBytes `json:"tee_tcb_svn2,omitempty"`
	MrServiceTD HexBytes `json:"mr_service_td,omitempty"`
	// SGX fields
	CPUSVN     HexBytes `json:"cpu_svn,omitempty"`
	MiscSelect *uint32  `json:"misc_select,omitempty"`
	Attributes HexBytes `json:"attributes,omitempty"`
	MrEnclave  HexBytes `json:"mr_enclave,omitempty"`
	MrSigner   HexBytes `json:"mr_signer,omitempty"`
	ISVProdID  *uint16  `json:"isv_prod_id,omitempty"`
	ISVSVN     *uint16  `json:"isv_svn,omitempty"`
}

// QuoteCollateralV3 holds collateral data for quote verification.
type QuoteCollateralV3 struct {
	PCKCRLIssuerChain     string   `json:"pck_crl_issuer_chain"`
	RootCACRL             HexBytes `json:"root_ca_crl"`
	PCKCRL                HexBytes `json:"pck_crl"`
	TCBInfoIssuerChain    string   `json:"tcb_info_issuer_chain"`
	TCBInfo               string   `json:"tcb_info"`
	TCBInfoSignature      HexBytes `json:"tcb_info_signature"`
	QEIdentityIssuerChain string   `json:"qe_identity_issuer_chain"`
	QEIdentity            string   `json:"qe_identity"`
	QEIdentitySignature   HexBytes `json:"qe_identity_signature"`
	PCKCertificateChain   string   `json:"pck_certificate_chain,omitempty"`
}

// VerifiedReport is the result of quote verification.
type VerifiedReport struct {
	Status         string                `json:"status"`
	AdvisoryIDs    []string              `json:"advisory_ids"`
	Report         QuoteReport           `json:"report"`
	PPID           HexBytes              `json:"ppid"`
	QEStatus       TcbStatusWithAdvisory `json:"qe_status"`
	PlatformStatus TcbStatusWithAdvisory `json:"platform_status"`
}

// TcbStatusWithAdvisory holds a TCB status and associated advisory IDs.
type TcbStatusWithAdvisory struct {
	Status      TcbStatus `json:"status"`
	AdvisoryIDs []string  `json:"advisory_ids"`
}

// TcbStatus represents the TCB level status.
type TcbStatus string

const (
	TcbStatusUpToDate                          TcbStatus = "UpToDate"
	TcbStatusOutOfDate                         TcbStatus = "OutOfDate"
	TcbStatusOutOfDateConfigurationNeeded      TcbStatus = "OutOfDateConfigurationNeeded"
	TcbStatusConfigurationNeeded               TcbStatus = "ConfigurationNeeded"
	TcbStatusSWHardeningNeeded                 TcbStatus = "SWHardeningNeeded"
	TcbStatusConfigurationAndSWHardeningNeeded TcbStatus = "ConfigurationAndSWHardeningNeeded"
	TcbStatusRevoked                           TcbStatus = "Revoked"
)

// PCKExtension holds parsed Intel SGX extension values from a PCK certificate.
type PCKExtension struct {
	PPID               HexBytes `json:"ppid"`
	CPUSVN             HexBytes `json:"cpu_svn"`
	PCESVN             uint16   `json:"pce_svn"`
	PCEID              HexBytes `json:"pce_id"`
	FMSPC              HexBytes `json:"fmspc"`
	SGXType            uint64   `json:"sgx_type"`
	PlatformInstanceID HexBytes `json:"platform_instance_id,omitempty"`
	RawExtension       HexBytes `json:"raw_extension"`
}

// Constants for well-known PCCS URLs.
const (
	PhalaPCCSURL = "https://pccs.phala.network"
	IntelPCSURL  = "https://api.trustedservices.intel.com"
)
