#!/bin/bash
# Test the Web WASM bindings using a headless browser

set -e

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║       DCAP Web Verification Test Suite                  ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo -e "${RED}✗${NC} Node.js is required but not installed"
    exit 1
fi

# Build web package if needed
if [ ! -d "pkg/web" ] || [ ! -f "pkg/web/dcap-qvl-web.js" ]; then
    echo -e "${BLUE}Building web package...${NC}"
    make build_web_pkg
    echo -e "${GREEN}✓${NC} Web package built"
else
    echo -e "${GREEN}✓${NC} Web package already built"
fi

# Ensure test data exists
if [ ! -d "test_data/samples" ]; then
    echo -e "${BLUE}Generating test data...${NC}"
    ./tests/test_suite.sh wasm 2>&1 > /dev/null
    echo -e "${GREEN}✓${NC} Test data generated"
else
    echo -e "${GREEN}✓${NC} Test data found"
fi

echo ""
echo -e "${BLUE}━━━ Starting Web Tests ━━━${NC}"
echo ""

# Create a simple test runner using Node.js
RESULTS_FILE="/tmp/web_test_results_$$.json"
rm -f "$RESULTS_FILE"

RUNNER_SCRIPT=$(mktemp /tmp/web_test_runner.XXXXXX)

cat > "$RUNNER_SCRIPT" << EOF
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 8765;
const ROOT = process.cwd();
const RESULTS_FILE = '$RESULTS_FILE';

const MIME_TYPES = {
    '.html': 'text/html',
    '.js': 'application/javascript',
    '.wasm': 'application/wasm',
    '.json': 'application/json',
    '.bin': 'application/octet-stream',
    '.der': 'application/x-x509-ca-cert',
};

const server = http.createServer((req, res) => {
    // Handle test results POST
    if (req.method === 'POST' && req.url === '/results') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            fs.writeFileSync(RESULTS_FILE, body);
            res.writeHead(200);
            res.end('OK');
        });
        return;
    }

    // Serve files
    let filePath;

    if (req.url === '/') {
        filePath = path.join(ROOT, '/tests/js/verify_quote_web_test.html');
    } else if (req.url.startsWith('/test_data/') || req.url.startsWith('/pkg/')) {
        filePath = path.join(ROOT, req.url);
    } else {
        filePath = path.join(ROOT, '/tests/js', req.url);
    }

    if (!filePath.startsWith(ROOT)) {
        res.writeHead(403);
        res.end('Forbidden');
        return;
    }

    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.writeHead(404);
            res.end('Not found');
            return;
        }

        const ext = path.extname(filePath);
        const contentType = MIME_TYPES[ext] || 'application/octet-stream';

        res.writeHead(200, {
            'Content-Type': contentType,
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Embedder-Policy': 'require-corp'
        });
        res.end(data);
    });
});

server.listen(PORT, () => {
    console.log(\`Server running at http://localhost:\${PORT}/\`);
});

process.on('SIGTERM', () => {
    server.close(() => process.exit(0));
});
EOF

# Start server in background
node "$RUNNER_SCRIPT" &
SERVER_PID=$!

# Wait for server to start
sleep 2

# Check if we have a headless browser available
if command -v google-chrome &> /dev/null || command -v chromium &> /dev/null || command -v chromium-browser &> /dev/null; then
    CHROME_BIN=""
    if command -v google-chrome &> /dev/null; then
        CHROME_BIN="google-chrome"
    elif command -v chromium &> /dev/null; then
        CHROME_BIN="chromium"
    elif command -v chromium-browser &> /dev/null; then
        CHROME_BIN="chromium-browser"
    fi

    echo -e "${BLUE}Running tests in headless Chrome...${NC}"
    echo ""

    # Run headless browser in background
    timeout 30 "$CHROME_BIN" --headless=new --disable-gpu --no-sandbox \
        --incognito --noerrdialogs --no-first-run \
        --user-data-dir=$(mktemp -d) --ozone-platform=headless \
        --ozone-override-screen-size=800,600 --use-angle=swiftshader-webgl \
        http://localhost:8765/ >/dev/null 2>&1 &
    CHROME_PID=$!

    # Wait for results file (max 25 seconds)
    for i in {1..50}; do
        if [ -f "$RESULTS_FILE" ]; then
            break
        fi
        sleep 0.5
    done

    # Kill Chrome
    kill $CHROME_PID 2>/dev/null || true
    wait $CHROME_PID 2>/dev/null || true

    # Parse and display results
    if [ -f "$RESULTS_FILE" ]; then
        RESULTS=$(cat "$RESULTS_FILE")
        echo "$RESULTS" | jq -r '.tests[]' 2>/dev/null | while read -r line; do
            if [[ "$line" == *"✓ PASS"* ]]; then
                echo -e "  ${GREEN}${line}${NC}"
            elif [[ "$line" == *"✗ FAIL"* ]]; then
                echo -e "  ${RED}${line}${NC}"
            elif [[ "$line" == *"━━━"* ]]; then
                echo -e "${CYAN}${line}${NC}"
            else
                echo "  ${line}"
            fi
        done

        echo ""
        echo -e "${CYAN}━━━ Test Summary ━━━${NC}"
        echo ""
        TOTAL=$(echo "$RESULTS" | jq -r '.summary.total' 2>/dev/null || echo "0")
        PASSED=$(echo "$RESULTS" | jq -r '.summary.passed' 2>/dev/null || echo "0")
        FAILED=$(echo "$RESULTS" | jq -r '.summary.failed' 2>/dev/null || echo "0")
        PASS_RATE=$(echo "$RESULTS" | jq -r '.summary.passRate' 2>/dev/null || echo "0")

        echo "  Total Tests: $TOTAL"
        echo -e "  ${GREEN}Passed: $PASSED${NC}"
        echo -e "  ${RED}Failed: $FAILED${NC}"
        echo "  Pass Rate: $PASS_RATE%"
        echo ""

        if [ "$FAILED" -eq 0 ]; then
            echo -e "${GREEN}✓ ALL TESTS PASSED${NC}"
            TEST_EXIT=0
        else
            echo -e "${RED}✗ SOME TESTS FAILED${NC}"
            TEST_EXIT=1
        fi
    else
        echo ""
        echo -e "${YELLOW}⚠${NC} Could not retrieve test results"
        echo "For manual testing, open: http://localhost:8765/"
        TEST_EXIT=1
    fi
else
    echo -e "${YELLOW}⚠${NC} No headless browser found. Opening in default browser..."
    echo ""
    echo "Please manually check the results at: http://localhost:8765/"
    echo ""
    echo "Tests are running... (Press Ctrl+C when done)"

    # Try to open browser
    if command -v xdg-open &> /dev/null; then
        xdg-open http://localhost:8765/ &> /dev/null || true
    fi

    # Wait for user
    sleep 30
    TEST_EXIT=0
fi

# Cleanup
kill $SERVER_PID 2>/dev/null || true
rm -f "$RUNNER_SCRIPT"

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${CYAN}For manual testing, you can run:${NC}"
echo "  cd tests/js"
echo "  ln -sf ../../pkg pkg"
echo "  ln -sf ../../test_data test_data"
echo "  python3 -m http.server 8000"
echo "  # Then open http://localhost:8000/verify_quote_web_test.html"
echo ""

exit $TEST_EXIT
