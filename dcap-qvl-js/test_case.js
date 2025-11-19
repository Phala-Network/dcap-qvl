#!/usr/bin/env node
/**
 * Pure JavaScript implementation of test_case CLI tool for DCAP quote verification.
 *
 * Usage:
 *     test_case.js <command> [args...]
 *
 * Commands:
 *     verify <quote_file> <collateral_file> [root_ca_file]
 *     get-collateral [--pccs-url URL] <quote_file>
 *
 * Exit codes:
 *     0 - Command successful
 *     1 - Command failed
 *     2 - Unexpected error (file not found, parse error, etc.)
 *
 * Output:
 *     Prints result to stdout
 *     Prints errors to stderr
 */

const fs = require('fs');
const path = require('path');
const { verify, QuoteVerifier } = require('./src/verify');
const { getCollateral } = require('./src/collateral');

function readFileAsUint8Array(filePath) {
    try {
        const data = fs.readFileSync(filePath);
        return new Uint8Array(data);
    } catch (e) {
        console.error(`Failed to read file ${filePath}: ${e.message}`);
        process.exit(2);
    }
}

function showHelp() {
    console.log("Pure JavaScript implementation of test_case CLI tool for DCAP quote verification");
    console.log("");
    console.log("Usage:");
    console.log("  test_case.js <command> [args...]");
    console.log("");
    console.log("Commands:");
    console.log("  verify <quote_file> <collateral_file> [root_ca_file]");
    console.log("    Verify a quote with collateral");
    console.log("  get-collateral [--pccs-url URL] <quote_file>");
    console.log("    Fetch collateral from PCCS");
    console.log("");
    console.log("Exit codes:");
    console.log("  0 - Command successful");
    console.log("  1 - Command failed");
    console.log("  2 - Unexpected error (file not found, parse error, etc.)");
}

async function cmdVerify(args) {
    const quoteFile = args[0];
    const collateralFile = args[1];
    const rootCaFile = args[2];

    if (!quoteFile || !collateralFile) {
        console.error("Error: Missing required arguments for verify command");
        console.error("Usage: test_case.js verify <quote_file> <collateral_file> [root_ca_file]");
        process.exit(2);
    }

    const quoteBytes = readFileAsUint8Array(quoteFile);

    let collateral;
    try {
        const collateralJson = fs.readFileSync(collateralFile, "utf8");
        collateral = JSON.parse(collateralJson);
    } catch (e) {
        console.error(`Failed to read collateral file: ${e.message}`);
        process.exit(2);
    }

    const rootCaDer = rootCaFile ? readFileAsUint8Array(rootCaFile) : null;

    const now = Math.floor(Date.now() / 1000);

    try {
        let result;
        if (rootCaDer) {
            const verifier = QuoteVerifier.newWithRootCa(Buffer.from(rootCaDer));
            result = verifier.verify(quoteBytes, collateral, now);
        } else {
            result = verify(quoteBytes, collateral, now);
        }

        console.log("Verification successful");
        console.log(`Status: ${result.status}`);
        process.exit(0);
    } catch (e) {
        // Format error chain
        let errorMsg = e.message;
        if (e.cause) {
            let cause = e.cause;
            while (cause) {
                errorMsg += `\n  Caused by: ${cause.message || cause}`;
                cause = cause.cause;
            }
        }
        console.error(`Verification failed: ${errorMsg}`);
        process.exit(1);
    }
}

async function cmdGetCollateral(args) {
    let quoteFile;
    let pccsUrl = "https://api.trustedservices.intel.com";

    // Parse arguments
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--pccs-url' && i + 1 < args.length) {
            pccsUrl = args[i + 1];
            i++; // Skip next argument
        } else if (!quoteFile) {
            quoteFile = args[i];
        }
    }

    if (!quoteFile) {
        console.error("Error: Missing quote file argument");
        console.error("Usage: test_case.js get-collateral [--pccs-url URL] <quote_file>");
        process.exit(2);
    }

    const quoteBytes = readFileAsUint8Array(quoteFile);

    try {
        const result = await getCollateral(pccsUrl, quoteBytes);

        if (!result || !result.tcb_info_issuer_chain) {
            console.error("Error: Collateral missing required fields");
            process.exit(1);
        }

        // Convert arrays back to hex strings for output (matching Rust/Python format)
        const outputCollateral = {
            pck_crl_issuer_chain: result.pck_crl_issuer_chain,
            root_ca_crl: Buffer.from(result.root_ca_crl).toString('hex'),
            pck_crl: Buffer.from(result.pck_crl).toString('hex'),
            tcb_info_issuer_chain: result.tcb_info_issuer_chain,
            tcb_info: result.tcb_info,
            tcb_info_signature: Buffer.from(result.tcb_info_signature).toString('hex'),
            qe_identity_issuer_chain: result.qe_identity_issuer_chain,
            qe_identity: result.qe_identity,
            qe_identity_signature: Buffer.from(result.qe_identity_signature).toString('hex'),
        };

        // Output collateral JSON directly (like Rust and Python versions)
        console.log(JSON.stringify(outputCollateral));
        process.exit(0);
    } catch (e) {
        console.error(`Get collateral failed: ${e.message}`);
        process.exit(1);
    }
}

async function main() {
    const args = process.argv.slice(2);

    if (args.length === 0 || args[0] === '--help' || args[0] === 'help') {
        showHelp();
        process.exit(0);
    }

    const command = args[0];
    const commandArgs = args.slice(1);

    switch (command) {
        case 'verify':
            await cmdVerify(commandArgs);
            break;
        case 'get-collateral':
            await cmdGetCollateral(commandArgs);
            break;
        default:
            console.error(`Error: Unknown command '${command}'`);
            console.error("Use 'test_case.js --help' for usage information");
            process.exit(2);
    }
}

main().catch(error => {
    console.error(`Unexpected error: ${error.message}`);
    console.error(error.stack);
    process.exit(2);
});
