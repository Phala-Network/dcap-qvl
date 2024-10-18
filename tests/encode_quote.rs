use dcap_qvl::quote::{
    AuthDataV3, AuthDataV4, CertificationData, EnclaveReport, Header, QEReportCertificationData,
    TDReport10, TDReport15,
};
use proptest::prelude::*;
use scale::{Decode, Encode};

proptest! {
    #[test]
    fn test_header_constraints(header: Header) {
        prop_assert!(header.version == 3 || header.version == 4 || header.version == 5);

        match header.version {
            3 => prop_assert_eq!(header.tee_type, 0x00000000),
            4 => prop_assert!(header.tee_type == 0x00000000 || header.tee_type == 0x00000081),
            5 => (),
            _ => panic!("Unexpected version"),
        }
    }

    #[test]
    fn test_header_encode_decode(header: Header) {
        let mut encoded = vec![];
        header.encode_to(&mut encoded);
        let decoded = Header::decode(&mut encoded.as_slice()).unwrap();
        prop_assert_eq!(header, decoded);
    }

    #[test]
    fn test_enclave_report_encode_decode(enclave_report: EnclaveReport) {
        let mut encoded = vec![];
        enclave_report.encode_to(&mut encoded);
        let decoded = EnclaveReport::decode(&mut encoded.as_slice()).unwrap();
        prop_assert_eq!(enclave_report, decoded);
    }

    #[test]
    fn test_tdreport10_encode_decode(tdreport10: TDReport10) {
        let mut encoded = vec![];
        tdreport10.encode_to(&mut encoded);
        let decoded = TDReport10::decode(&mut encoded.as_slice()).unwrap();
        prop_assert_eq!(tdreport10, decoded);
    }

    #[test]
    fn test_tdreport15_encode_decode(tdreport15: TDReport15) {
        let mut encoded = vec![];
        tdreport15.encode_to(&mut encoded);
        let decoded = TDReport15::decode(&mut encoded.as_slice()).unwrap();
        prop_assert_eq!(tdreport15, decoded);
    }

    #[test]
    fn test_certification_data_encode_decode(certification_data: CertificationData) {
        let mut encoded = vec![];
        certification_data.encode_to(&mut encoded);
        let decoded = CertificationData::decode(&mut encoded.as_slice()).unwrap();
        prop_assert_eq!(certification_data, decoded);
    }

    #[test]
    fn test_qe_report_certification_data_encode_decode(qe_report_certification_data: QEReportCertificationData) {
        let mut encoded = vec![];
        qe_report_certification_data.encode_to(&mut encoded);
        let decoded = QEReportCertificationData::decode(&mut encoded.as_slice()).unwrap();
        prop_assert_eq!(qe_report_certification_data, decoded);
    }

    #[test]
    fn test_auth_data_v3_encode_decode(auth_data_v3: AuthDataV3) {
        let mut encoded = vec![];
        auth_data_v3.encode_to(&mut encoded);
        let decoded = AuthDataV3::decode(&mut encoded.as_slice()).unwrap();
        prop_assert_eq!(auth_data_v3, decoded);
    }

    #[test]
    fn test_auth_data_v4_encode_decode(auth_data_v4: AuthDataV4) {
        let mut encoded = vec![];
        auth_data_v4.encode_to(&mut encoded);
        let decoded = AuthDataV4::decode(&mut encoded.as_slice()).unwrap();
        prop_assert_eq!(auth_data_v4, decoded);
    }
}
