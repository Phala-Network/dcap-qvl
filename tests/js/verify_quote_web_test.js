import init, { js_verify, js_verify_with_root_ca, js_get_collateral } from "/pkg/web/dcap-qvl-web.js";

const testOutputs = [];
let passed = 0;
let failed = 0;

function log(message, isPass = null) {
    // Build output string
    let output;
    if (isPass === true) {
        output = '✓ PASS: ' + message;
        console.log(output);
        passed++;
    } else if (isPass === false) {
        output = '✗ FAIL: ' + message;
        console.error(output);
        failed++;
    } else {
        output = message;
        console.log(message);
    }

    // Store for reporting
    testOutputs.push(output);

    // Also update DOM for browser display
    const resultsDiv = document.getElementById('results');
    if (resultsDiv) {
        const div = document.createElement('div');
        div.className = 'test-result';
        if (isPass === true) {
            div.classList.add('pass');
            div.textContent = '✓ ' + message;
        } else if (isPass === false) {
            div.classList.add('fail');
            div.textContent = '✗ ' + message;
        } else {
            div.textContent = message;
        }
        resultsDiv.appendChild(div);
    }
}

async function fetchFile(url) {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`Failed to fetch ${url}`);
    return new Uint8Array(await response.arrayBuffer());
}

async function fetchJSON(url) {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`Failed to fetch ${url}`);
    return await response.json();
}

async function runTest(name, testFn) {
    try {
        await testFn();
        log(`${name}: PASS`, true);
        return true;
    } catch (error) {
        const message = typeof error === 'object' && error !== null && 'message' in error
            ? /** @type {{ message?: string }} */ (error).message || 'Unknown error'
            : String(error);
        log(`${name}: FAIL - ${message}`, false);
        console.error(`Error details for ${name}:`, error);
        return false;
    }
}

async function runTests() {
    document.getElementById('status').textContent = 'Initializing WASM...';

    try {
        await init("/pkg/web/dcap-qvl-web_bg.wasm");
        log('WASM module initialized');
    } catch (error) {
        log(`Failed to initialize WASM: ${error.message}`, false);
        return;
    }

    document.getElementById('status').textContent = 'Running tests...';
    log('');
    log('━━━ Valid Quotes ━━━');

    // Test valid SGX quote v3
    await runTest('Valid SGX v3 quote', async () => {
        const quote = await fetchFile('/test_data/samples/valid_sgx_v3/quote.bin');
        const collateral = await fetchJSON('/test_data/samples/valid_sgx_v3/collateral.json');
        const rootCA = await fetchFile('/test_data/certs/root_ca.der');
        const now = BigInt(Math.floor(Date.now() / 1000));

        const result = js_verify_with_root_ca(quote, collateral, rootCA, now);
        if (!result || !result.status) {
            throw new Error('Verification should succeed but got no result');
        }
    });

    // Test valid SGX quote v4
    await runTest('Valid SGX v4 quote', async () => {
        const quote = await fetchFile('/test_data/samples/valid_sgx_v4/quote.bin');
        const collateral = await fetchJSON('/test_data/samples/valid_sgx_v4/collateral.json');
        const rootCA = await fetchFile('/test_data/certs/root_ca.der');
        const now = BigInt(Math.floor(Date.now() / 1000));

        const result = js_verify_with_root_ca(quote, collateral, rootCA, now);
        if (!result || !result.status) {
            throw new Error('Verification should succeed but got no result');
        }
    });

    // Test valid SGX quote v5
    await runTest('Valid SGX v5 quote', async () => {
        const quote = await fetchFile('/test_data/samples/valid_sgx_v5/quote.bin');
        const collateral = await fetchJSON('/test_data/samples/valid_sgx_v5/collateral.json');
        const rootCA = await fetchFile('/test_data/certs/root_ca.der');
        const now = BigInt(Math.floor(Date.now() / 1000));

        const result = js_verify_with_root_ca(quote, collateral, rootCA, now);
        if (!result || !result.status) {
            throw new Error('Verification should succeed but got no result');
        }
    });

    // Test valid TDX quote
    await runTest('Valid TDX v4 quote', async () => {
        const quote = await fetchFile('/test_data/samples/valid_tdx_v4/quote.bin');
        const collateral = await fetchJSON('/test_data/samples/valid_tdx_v4/collateral.json');
        const rootCA = await fetchFile('/test_data/certs/root_ca.der');
        const now = BigInt(Math.floor(Date.now() / 1000));

        const result = js_verify_with_root_ca(quote, collateral, rootCA, now);
        if (!result || !result.status) {
            throw new Error('Verification should succeed but got no result');
        }
    });

    log('');
    log('━━━ Decode Errors ━━━');

    // Test invalid quote should fail
    await runTest('Invalid quote format should fail', async () => {
        const quote = await fetchFile('/test_data/samples/invalid_quote_format/quote.bin');
        const collateral = await fetchJSON('/test_data/samples/invalid_quote_format/collateral.json');
        const rootCA = await fetchFile('/test_data/certs/root_ca.der');
        const now = BigInt(Math.floor(Date.now() / 1000));

        try {
            const result = js_verify_with_root_ca(quote, collateral, rootCA, now);
            throw new Error('Should have failed but succeeded');
        } catch (error) {
            // WASM errors might be strings or objects
            const errorStr = typeof error === 'string' ? error : (error.message || String(error));
            if (!errorStr.includes('Failed to decode quote')) {
                throw new Error(`Expected decode error but got: ${errorStr}`);
            }
        }
    });

    // Test truncated quote
    await runTest('Truncated quote', async () => {
        const quote = await fetchFile('/test_data/samples/truncated_quote/quote.bin');
        const collateral = await fetchJSON('/test_data/samples/truncated_quote/collateral.json');
        const rootCA = await fetchFile('/test_data/certs/root_ca.der');
        const now = BigInt(Math.floor(Date.now() / 1000));

        try {
            const result = js_verify_with_root_ca(quote, collateral, rootCA, now);
            throw new Error('Should have failed but succeeded');
        } catch (error) {
            // WASM errors might be strings or objects
            const errorStr = typeof error === 'string' ? error : (error.message || String(error));
            if (!errorStr.includes('Not enough data to fill buffer')) {
                throw new Error(`Expected "Not enough data" error but got: ${errorStr}`);
            }
        }
    });

    // Test invalid quote v5
    await runTest('Invalid quote v5 format', async () => {
        const quote = await fetchFile('/test_data/samples/invalid_quote_v5/quote.bin');
        const collateral = await fetchJSON('/test_data/samples/invalid_quote_v5/collateral.json');
        const rootCA = await fetchFile('/test_data/certs/root_ca.der');
        const now = BigInt(Math.floor(Date.now() / 1000));

        try {
            const result = js_verify_with_root_ca(quote, collateral, rootCA, now);
            throw new Error('Should have failed but succeeded');
        } catch (error) {
            const errorStr = typeof error === 'string' ? error : (error.message || String(error));
            if (!errorStr.includes('Isv enclave report signature is invalid')) {
                throw new Error(`Expected signature error but got: ${errorStr}`);
            }
        }
    });

    log('');
    log('━━━ Debug Mode ━━━');

    // Test debug mode detection SGX v3
    await runTest('Debug SGX v3', async () => {
        const quote = await fetchFile('/test_data/samples/debug_sgx_v3/quote.bin');
        const collateral = await fetchJSON('/test_data/samples/debug_sgx_v3/collateral.json');
        const rootCA = await fetchFile('/test_data/certs/root_ca.der');
        const now = BigInt(Math.floor(Date.now() / 1000));

        try {
            const result = js_verify_with_root_ca(quote, collateral, rootCA, now);
            throw new Error('Should have failed but succeeded');
        } catch (error) {
            // WASM errors might be strings or objects
            const errorStr = typeof error === 'string' ? error : (error.message || String(error));
            if (!errorStr.includes('Debug mode is enabled')) {
                throw new Error(`Expected debug mode error but got: ${errorStr}`);
            }
        }
    });

    // Test debug mode detection SGX v4
    await runTest('Debug SGX v4', async () => {
        const quote = await fetchFile('/test_data/samples/debug_sgx_v4/quote.bin');
        const collateral = await fetchJSON('/test_data/samples/debug_sgx_v4/collateral.json');
        const rootCA = await fetchFile('/test_data/certs/root_ca.der');
        const now = BigInt(Math.floor(Date.now() / 1000));

        try {
            const result = js_verify_with_root_ca(quote, collateral, rootCA, now);
            throw new Error('Should have failed but succeeded');
        } catch (error) {
            const errorStr = typeof error === 'string' ? error : (error.message || String(error));
            if (!errorStr.includes('Debug mode is enabled')) {
                throw new Error(`Expected debug mode error but got: ${errorStr}`);
            }
        }
    });

    log('');
    log('━━━ Version Errors ━━━');

    // Test unsupported version 1
    await runTest('Unsupported version 1', async () => {
        const quote = await fetchFile('/test_data/samples/unsupported_version_1/quote.bin');
        const collateral = await fetchJSON('/test_data/samples/unsupported_version_1/collateral.json');
        const rootCA = await fetchFile('/test_data/certs/root_ca.der');
        const now = BigInt(Math.floor(Date.now() / 1000));

        try {
            const result = js_verify_with_root_ca(quote, collateral, rootCA, now);
            throw new Error('Should have failed but succeeded');
        } catch (error) {
            const errorStr = typeof error === 'string' ? error : (error.message || String(error));
            if (!errorStr.includes('Unsupported')) {
                throw new Error(`Expected unsupported version error but got: ${errorStr}`);
            }
        }
    });

    // Test unsupported version 6
    await runTest('Unsupported version 6', async () => {
        const quote = await fetchFile('/test_data/samples/unsupported_version_6/quote.bin');
        const collateral = await fetchJSON('/test_data/samples/unsupported_version_6/collateral.json');
        const rootCA = await fetchFile('/test_data/certs/root_ca.der');
        const now = BigInt(Math.floor(Date.now() / 1000));

        try {
            const result = js_verify_with_root_ca(quote, collateral, rootCA, now);
            throw new Error('Should have failed but succeeded');
        } catch (error) {
            const errorStr = typeof error === 'string' ? error : (error.message || String(error));
            if (!errorStr.includes('Unsupported')) {
                throw new Error(`Expected unsupported version error but got: ${errorStr}`);
            }
        }
    });

    log('');
    log('━━━ Key Type Errors ━━━');

    // Test unsupported key type 0
    await runTest('Unsupported key type 0', async () => {
        const quote = await fetchFile('/test_data/samples/unsupported_key_type_0/quote.bin');
        const collateral = await fetchJSON('/test_data/samples/unsupported_key_type_0/collateral.json');
        const rootCA = await fetchFile('/test_data/certs/root_ca.der');
        const now = BigInt(Math.floor(Date.now() / 1000));

        try {
            const result = js_verify_with_root_ca(quote, collateral, rootCA, now);
            throw new Error('Should have failed but succeeded');
        } catch (error) {
            const errorStr = typeof error === 'string' ? error : (error.message || String(error));
            if (!errorStr.includes('Unsupported DCAP attestation key type')) {
                throw new Error(`Expected key type error but got: ${errorStr}`);
            }
        }
    });

    log('');
    log('━━━ TCB Errors ━━━');

    // Test TCB expired
    await runTest('TCB expired', async () => {
        const quote = await fetchFile('/test_data/samples/tcb_expired/quote.bin');
        const collateral = await fetchJSON('/test_data/samples/tcb_expired/collateral.json');
        const rootCA = await fetchFile('/test_data/certs/root_ca.der');
        const now = BigInt(Math.floor(Date.now() / 1000));

        try {
            const result = js_verify_with_root_ca(quote, collateral, rootCA, now);
            throw new Error('Should have failed but succeeded');
        } catch (error) {
            const errorStr = typeof error === 'string' ? error : (error.message || String(error));
            if (!errorStr.includes('TCBInfo expired')) {
                throw new Error(`Expected TCB expired error but got: ${errorStr}`);
            }
        }
    });

    // Test invalid TCB JSON
    await runTest('Invalid TCB JSON', async () => {
        const quote = await fetchFile('/test_data/samples/invalid_tcb_json/quote.bin');
        const collateral = await fetchJSON('/test_data/samples/invalid_tcb_json/collateral.json');
        const rootCA = await fetchFile('/test_data/certs/root_ca.der');
        const now = BigInt(Math.floor(Date.now() / 1000));

        try {
            const result = js_verify_with_root_ca(quote, collateral, rootCA, now);
            throw new Error('Should have failed but succeeded');
        } catch (error) {
            const errorStr = typeof error === 'string' ? error : (error.message || String(error));
            if (!errorStr.includes('Failed to decode TcbInfo')) {
                throw new Error(`Expected TCB JSON error but got: ${errorStr}`);
            }
        }
    });

    log('');
    log('━━━ Signature Errors ━━━');

    // Test invalid quote signature
    await runTest('Invalid quote signature', async () => {
        const quote = await fetchFile('/test_data/samples/invalid_quote_signature/quote.bin');
        const collateral = await fetchJSON('/test_data/samples/invalid_quote_signature/collateral.json');
        const rootCA = await fetchFile('/test_data/certs/root_ca.der');
        const now = BigInt(Math.floor(Date.now() / 1000));

        try {
            const result = js_verify_with_root_ca(quote, collateral, rootCA, now);
            throw new Error('Should have failed but succeeded');
        } catch (error) {
            const errorStr = typeof error === 'string' ? error : (error.message || String(error));
            if (!errorStr.includes('signature is invalid')) {
                throw new Error(`Expected signature error but got: ${errorStr}`);
            }
        }
    });

    log('');
    log('━━━ FMSPC Errors ━━━');

    // Test FMSPC mismatch
    await runTest('FMSPC mismatch', async () => {
        const quote = await fetchFile('/test_data/samples/fmspc_mismatch/quote.bin');
        const collateral = await fetchJSON('/test_data/samples/fmspc_mismatch/collateral.json');
        const rootCA = await fetchFile('/test_data/certs/root_ca.der');
        const now = BigInt(Math.floor(Date.now() / 1000));

        try {
            const result = js_verify_with_root_ca(quote, collateral, rootCA, now);
            throw new Error('Should have failed but succeeded');
        } catch (error) {
            const errorStr = typeof error === 'string' ? error : (error.message || String(error));
            if (!errorStr.includes('Fmspc mismatch')) {
                throw new Error(`Expected FMSPC error but got: ${errorStr}`);
            }
        }
    });

    log('');
    log('━━━ TDX-Specific Errors ━━━');

    // Test TDX debug enabled
    await runTest('TDX debug enabled', async () => {
        const quote = await fetchFile('/test_data/samples/tdx_debug_enabled/quote.bin');
        const collateral = await fetchJSON('/test_data/samples/tdx_debug_enabled/collateral.json');
        const rootCA = await fetchFile('/test_data/certs/root_ca.der');
        const now = BigInt(Math.floor(Date.now() / 1000));

        try {
            const result = js_verify_with_root_ca(quote, collateral, rootCA, now);
            throw new Error('Should have failed but succeeded');
        } catch (error) {
            const errorStr = typeof error === 'string' ? error : (error.message || String(error));
            if (!errorStr.includes('Debug mode is enabled')) {
                throw new Error(`Expected debug mode error but got: ${errorStr}`);
            }
        }
    });

    // Test TDX PKS enabled (should succeed)
    await runTest("TDX PKS enabled", async () => {
        const quote = await fetchFile(
            "/test_data/samples/tdx_pks_enabled/quote.bin"
        );
        const collateral = await fetchJSON(
            "/test_data/samples/tdx_pks_enabled/collateral.json"
        );
        const rootCA = await fetchFile("/test_data/certs/root_ca.der");
        const now = BigInt(Math.floor(Date.now() / 1000));

        const result = js_verify_with_root_ca(quote, collateral, rootCA, now);
        if (!result || !result.status) {
            throw new Error(
                "Verification should succeed for PKS enabled quote"
            );
        }
    });

    log('');
    log('━━━ Collateral Fetching ━━━');

    // Test get_collateral functionality - should work exactly like Node.js
    await runTest('Fetch collateral from PCCS', async () => {
        const quote = await fetchFile('/sample/tdx_quote');

        // Check if get_collateral function is available in Web WASM
        if (typeof js_get_collateral !== 'function') {
            throw new Error('js_get_collateral function not available in Web WASM');
        }

        // Test with HTTP URL (our mock server runs on HTTP)
        const mockPccsUrl = 'http://localhost:8765/tdx/certification/v4';
        const result = js_get_collateral(mockPccsUrl, quote);

        // The function should return a promise in Web WASM just like in Node.js
        if (!result || typeof result.then !== 'function') {
            throw new Error('WASM get_collateral did not return a promise, got: ' + typeof result);
        }

        // Wait for the get_collateral function to complete
        const collateral = await result;

        // Validate that collateral has all required fields (same validation as Node.js)
        if (!collateral) {
            throw new Error('get_collateral returned null/undefined');
        }

        if (!collateral.tcb_info_issuer_chain) {
            throw new Error('Collateral missing tcb_info_issuer_chain');
        }

        if (!collateral.pck_crl_issuer_chain) {
            throw new Error('Collateral missing pck_crl_issuer_chain');
        }

        if (!collateral.tcb_info) {
            throw new Error('Collateral missing tcb_info');
        }

        if (!collateral.qe_identity) {
            throw new Error('Collateral missing qe_identity');
        }

        // Verify certificate chains start with BEGIN CERTIFICATE
        if (!collateral.tcb_info_issuer_chain.startsWith('-----BEGIN CERTIFICATE-----')) {
            throw new Error('Invalid tcb_info_issuer_chain format');
        }

        if (!collateral.pck_crl_issuer_chain.startsWith('-----BEGIN CERTIFICATE-----')) {
            throw new Error('Invalid pck_crl_issuer_chain format');
        }

        log('Successfully fetched collateral using Web WASM get_collateral');
    });

    // Summary
    const total = passed + failed;
    const passRate = total > 0 ? ((passed / total) * 100).toFixed(1) : 0;

    log('');
    log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    log(`Total: ${total} tests`);
    log(`Passed: ${passed}`);
    if (failed > 0) {
        log(`Failed: ${failed}`);
    }
    log(`Pass rate: ${passRate}%`);

    // Console summary for headless testing
    console.log('\n=== TEST SUMMARY ===');
    console.log(`Total Tests: ${total}`);
    console.log(`Passed: ${passed}`);
    console.log(`Failed: ${failed}`);
    console.log(`Pass Rate: ${passRate}%`);
    console.log(failed === 0 ? '✓ ALL TESTS PASSED' : '✗ SOME TESTS FAILED');
    console.log('====================\n');

    const statusDiv = document.getElementById('status');
    if (statusDiv) {
        statusDiv.textContent = failed === 0 ? 'All tests passed! ✓' : `${failed} test(s) failed ✗`;
    }

    // Set exit code for headless testing
    window.testResults = { passed, failed, total, passRate };

    // POST results to server for headless testing
    try {
        await fetch('/results', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                tests: testOutputs,
                summary: {
                    total,
                    passed,
                    failed,
                    passRate
                }
            })
        });
    } catch (e) {
        console.error('Failed to send results to server:', e);
    }
}

runTests().catch(error => {
    log(`Test suite error: ${error.message}`, false);
    console.error(error);
});
