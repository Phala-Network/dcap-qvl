// Main entry point for dcap-qvl-js
// Pure JavaScript implementation of DCAP Quote Verification Library

const { Quote } = require('./quote');
const { verify, QuoteVerifier, VerifiedReport } = require('./verify');
const { getCollateral, getCollateralFromPcs, getCollateralAndVerify, PHALA_PCCS_URL, INTEL_PCS_URL } = require('./collateral');
const { TcbInfo } = require('./tcb_info');
const constants = require('./constants');
const oids = require('./oids');
const utils = require('./utils');
const intel = require('./intel');
const { isBrowser } = require('./crypto-compat');

module.exports = {
    // Quote parsing
    Quote,

    // Verification
    verify,
    QuoteVerifier,
    VerifiedReport,

    // Browser mode control
    isBrowser,

    // Collateral fetching
    getCollateral,
    getCollateralFromPcs,
    getCollateralAndVerify,
    PHALA_PCCS_URL,
    INTEL_PCS_URL,

    // TCB Info
    TcbInfo,

    // Utilities
    utils,
    intel,
    constants,
    oids,
};
