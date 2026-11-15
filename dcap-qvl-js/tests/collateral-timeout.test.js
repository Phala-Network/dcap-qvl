const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { getCollateralForFmspc } = require('../src/collateral');

function listen(server) {
    return new Promise((resolve) => {
        server.listen(0, '127.0.0.1', () => resolve(server.address().port));
    });
}

async function withServer(handler, fn) {
    const server = http.createServer(handler);
    const port = await listen(server);
    try {
        await fn(`http://127.0.0.1:${port}`);
    } finally {
        server.closeAllConnections?.();
        server.close();
    }
}

const ARGS = ['FMSPC', 'processor', false];

test('collateral fetch rejects at the deadline when the server never responds', async () => {
    await withServer(() => { /* accept but never respond */ }, async (url) => {
        const start = Date.now();
        await assert.rejects(
            getCollateralForFmspc(url, ...ARGS, { timeoutMs: 150 }),
            /timed out/,
        );
        assert.ok(Date.now() - start < 2000, 'must reject at the deadline, not hang indefinitely');
    });
});

test('collateral fetch deadline covers the response body, not just the headers', async () => {
    await withServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
        res.write('partial');
        // never end the response
    }, async (url) => {
        const start = Date.now();
        await assert.rejects(
            getCollateralForFmspc(url, ...ARGS, { timeoutMs: 150 }),
            /timed out/,
        );
        assert.ok(Date.now() - start < 2000, 'must reject at the deadline, not hang indefinitely');
    });
});

test('pre-aborted caller signal rejects immediately', async () => {
    await withServer(() => {}, async (url) => {
        const controller = new AbortController();
        controller.abort();
        await assert.rejects(
            getCollateralForFmspc(url, ...ARGS, { signal: controller.signal, timeoutMs: 5000 }),
            (error) => error.name === 'AbortError',
        );
    });
});

test('caller signal aborts an in-flight collateral fetch', async () => {
    await withServer(() => { /* hang forever */ }, async (url) => {
        const controller = new AbortController();
        const promise = getCollateralForFmspc(url, ...ARGS, {
            signal: controller.signal,
            timeoutMs: 5000,
        });
        const timer = setTimeout(() => controller.abort(), 100);
        try {
            await assert.rejects(promise, (error) => error.name === 'AbortError');
        } finally {
            clearTimeout(timer);
        }
    });
});

test('HTTP error statuses still surface unchanged', async () => {
    await withServer((req, res) => {
        res.writeHead(404);
        res.end('not found');
    }, async (url) => {
        await assert.rejects(
            getCollateralForFmspc(url, ...ARGS, { timeoutMs: 1000 }),
            /Failed to fetch .* 404/,
        );
    });
});

test('timeoutMs 0 disables the deadline', async () => {
    await withServer((req, res) => {
        // Answers slower than the short deadline below, but well within the default.
        setTimeout(() => {
            res.writeHead(404);
            res.end('late');
        }, 300);
    }, async (url) => {
        // With a deadline shorter than the server's response time, the call rejects.
        const start = Date.now();
        await assert.rejects(
            getCollateralForFmspc(url, ...ARGS, { timeoutMs: 100 }),
            /timed out/,
        );
        assert.ok(Date.now() - start < 2000, 'must reject at the deadline');
        // timeoutMs 0 opts out: the same slow server now gets to answer.
        await assert.rejects(getCollateralForFmspc(url, ...ARGS, { timeoutMs: 0 }), /404/);
    });
});
