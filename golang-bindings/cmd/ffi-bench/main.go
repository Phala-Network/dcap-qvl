package main

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	dcap "github.com/Phala-Network/dcap-qvl/golang-bindings"
)

type benchResult struct {
	Mode       string `json:"mode"`
	Iterations int    `json:"iterations"`
	DurationMs int64  `json:"duration_ms"`
	RSSStartKB uint64 `json:"rss_start_kb"`
	RSSEndKB   uint64 `json:"rss_end_kb"`
	RSSDeltaKB int64  `json:"rss_delta_kb"`
}

func sampleDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "..", "sample")
}

func loadSample() ([]byte, *dcap.QuoteCollateralV3, uint64, error) {
	dir := sampleDir()
	quote, err := os.ReadFile(filepath.Join(dir, "sgx_quote"))
	if err != nil {
		return nil, nil, 0, err
	}
	collJSON, err := os.ReadFile(filepath.Join(dir, "sgx_quote_collateral.json"))
	if err != nil {
		return nil, nil, 0, err
	}
	var coll dcap.QuoteCollateralV3
	if err := json.Unmarshal(collJSON, &coll); err != nil {
		return nil, nil, 0, err
	}
	now, err := nowFromCollateral(&coll)
	if err != nil {
		return nil, nil, 0, err
	}
	return quote, &coll, now, nil
}

func nowFromCollateral(coll *dcap.QuoteCollateralV3) (uint64, error) {
	parseIssueNext := func(jsonStr string) (uint64, uint64, error) {
		var obj struct {
			IssueDate  string `json:"issueDate"`
			NextUpdate string `json:"nextUpdate"`
		}
		if err := json.Unmarshal([]byte(jsonStr), &obj); err != nil {
			return 0, 0, err
		}
		issue, err := time.Parse(time.RFC3339, obj.IssueDate)
		if err != nil {
			return 0, 0, err
		}
		next, err := time.Parse(time.RFC3339, obj.NextUpdate)
		if err != nil {
			return 0, 0, err
		}
		return uint64(issue.Unix()), uint64(next.Unix()), nil
	}

	parseCRLBounds := func(crlDER []byte) (uint64, *uint64, error) {
		crl, err := x509.ParseRevocationList(crlDER)
		if err != nil {
			return 0, nil, err
		}
		thisUpdate := uint64(crl.ThisUpdate.Unix())
		if !crl.NextUpdate.IsZero() {
			nu := uint64(crl.NextUpdate.Unix())
			return thisUpdate, &nu, nil
		}
		return thisUpdate, nil, nil
	}

	tcbIssue, tcbNext, err := parseIssueNext(coll.TCBInfo)
	if err != nil {
		return 0, err
	}
	qeIssue, qeNext, err := parseIssueNext(coll.QEIdentity)
	if err != nil {
		return 0, err
	}

	notBefore := tcbIssue
	if qeIssue > notBefore {
		notBefore = qeIssue
	}
	notAfter := tcbNext
	if qeNext < notAfter {
		notAfter = qeNext
	}

	for _, crlDER := range [][]byte{coll.RootCACRL, coll.PCKCRL} {
		thisUpdate, nextUpdate, err := parseCRLBounds(crlDER)
		if err != nil {
			return 0, err
		}
		if thisUpdate > notBefore {
			notBefore = thisUpdate
		}
		if nextUpdate != nil && *nextUpdate < notAfter {
			notAfter = *nextUpdate
		}
	}

	if notBefore > notAfter {
		return 0, fmt.Errorf("invalid collateral validity window")
	}
	if notAfter > notBefore {
		return notAfter - 1, nil
	}
	return notAfter, nil
}

func rssKB() uint64 {
	pid := os.Getpid()
	out, err := exec.Command("ps", "-o", "rss=", "-p", fmt.Sprintf("%d", pid)).Output()
	if err != nil {
		return 0
	}
	var v uint64
	_, _ = fmt.Sscanf(string(out), "%d", &v)
	return v
}

func main() {
	mode := flag.String("mode", "parse", "benchmark mode: parse|verify")
	iterations := flag.Int("iterations", 100000, "number of iterations")
	flag.Parse()

	quote, coll, now, err := loadSample()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load sample failed: %v\n", err)
		os.Exit(1)
	}

	// Warmup
	switch *mode {
	case "parse":
		_, err = dcap.ParseQuote(quote)
	case "verify":
		_, err = dcap.Verify(quote, coll, now)
	default:
		fmt.Fprintf(os.Stderr, "invalid mode: %s\n", *mode)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "warmup failed: %v\n", err)
		os.Exit(1)
	}

	startRSS := rssKB()
	start := time.Now()

	for i := 0; i < *iterations; i++ {
		switch *mode {
		case "parse":
			_, err = dcap.ParseQuote(quote)
		case "verify":
			_, err = dcap.Verify(quote, coll, now)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "iteration %d failed: %v\n", i, err)
			os.Exit(1)
		}
	}

	duration := time.Since(start)
	endRSS := rssKB()

	res := benchResult{
		Mode:       *mode,
		Iterations: *iterations,
		DurationMs: duration.Milliseconds(),
		RSSStartKB: startRSS,
		RSSEndKB:   endRSS,
		RSSDeltaKB: int64(endRSS) - int64(startRSS),
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
}
