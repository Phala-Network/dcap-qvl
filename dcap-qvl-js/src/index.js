// Main entry point for dcap-qvl-js
// Pure JavaScript implementation of DCAP Quote Verification Library

const { Quote } = require('./quote');
const { verify, QuoteVerifier, VerifiedReport } = require('./verify');
const { getCollateral, getCollateralFromPcs, getCollateralAndVerify } = require('./collateral');
const { TcbInfo } = require('./tcb_info');
const constants = require('./constants');
const oids = require('./oids');
const utils = require('./utils');
const intel = require('./intel');

module.exports = {
    // Quote parsing
    Quote,

    // Verification
    verify,
    QuoteVerifier,
    VerifiedReport,

    // Collateral fetching
    getCollateral,
    getCollateralFromPcs,
    getCollateralAndVerify,

    // TCB Info
    TcbInfo,

    // Utilities
    utils,
    intel,
    constants,
    oids,
};
