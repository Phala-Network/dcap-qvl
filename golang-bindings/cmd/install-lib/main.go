package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	defaultRepo       = "Phala-Network/dcap-qvl"
	defaultVersion    = "latest"
	defaultChecksums  = "checksums.txt"
	defaultAPIRoot    = "https://api.github.com"
	defaultReleaseURL = "https://github.com"
)

type latestReleaseResponse struct {
	TagName string `json:"tag_name"`
}

type httpStatusError struct {
	URL        string
	Status     string
	StatusCode int
	Body       string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("GET %s failed: %s: %s", e.URL, e.Status, e.Body)
}

func main() {
	var version string
	var repo string
	var installDir string
	var timeout time.Duration
	var printEnvOnly bool

	flag.StringVar(&version, "version", defaultVersion, "release version tag, e.g. v0.3.13 (or 'latest')")
	flag.StringVar(&repo, "repo", defaultRepo, "GitHub repo in owner/name format")
	flag.StringVar(&installDir, "dir", "", "install directory for libdcap_qvl.a (default: per-user cache)")
	flag.DurationVar(&timeout, "timeout", 60*time.Second, "HTTP timeout")
	flag.BoolVar(&printEnvOnly, "print-env", false, "print only CGO_LDFLAGS assignment for scripting")
	flag.Parse()

	goos := runtime.GOOS
	goarch := runtime.GOARCH
	assetName, err := platformAssetName(goos, goarch)
	if err != nil {
		fatal(err)
	}

	client := &http.Client{Timeout: timeout}
	ctx := context.Background()

	resolvedVersion := version
	if version == defaultVersion {
		resolvedVersion, err = fetchLatestReleaseTag(ctx, client, defaultAPIRoot, repo)
		if err != nil {
			fatal(fmt.Errorf("resolve latest release version: %w", err))
		}
	}

	if installDir == "" {
		installDir, err = defaultInstallDir(resolvedVersion, goos, goarch)
		if err != nil {
			fatal(err)
		}
	}
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		fatal(fmt.Errorf("create install dir %q: %w", installDir, err))
	}

	checksumsURL := releaseAssetURL(defaultReleaseURL, repo, resolvedVersion, defaultChecksums)
	checksumBytes, err := downloadBytes(ctx, client, checksumsURL)
	if err != nil {
		if isHTTPStatus(err, http.StatusNotFound) {
			fatal(fmt.Errorf(
				"release %s in %s does not include %s; Go static library assets are not published for this version yet. Build from source with `cargo build --release --features go` and set CGO_LDFLAGS to your `target/release` directory",
				resolvedVersion,
				repo,
				defaultChecksums,
			))
		}
		fatal(fmt.Errorf("download checksums: %w", err))
	}
	checksums, err := parseChecksums(string(checksumBytes))
	if err != nil {
		fatal(fmt.Errorf("parse checksums: %w", err))
	}

	expectedSHA, ok := checksums[assetName]
	if !ok {
		fatal(fmt.Errorf("checksum for %s not found in %s", assetName, defaultChecksums))
	}

	targetPath := filepath.Join(installDir, "libdcap_qvl.a")
	if matches, err := fileMatchesSHA256(targetPath, expectedSHA); err == nil && matches {
		printResult(targetPath, installDir, printEnvOnly)
		return
	}

	assetURL := releaseAssetURL(defaultReleaseURL, repo, resolvedVersion, assetName)
	tmpFile, err := os.CreateTemp(installDir, "libdcap_qvl.a.tmp-*")
	if err != nil {
		fatal(fmt.Errorf("create temp file: %w", err))
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	if err := downloadToWriter(ctx, client, assetURL, tmpFile); err != nil {
		if isHTTPStatus(err, http.StatusNotFound) {
			fatal(fmt.Errorf(
				"release %s in %s does not include %s for %s/%s. Build from source with `cargo build --release --features go` and set CGO_LDFLAGS to your `target/release` directory",
				resolvedVersion,
				repo,
				assetName,
				goos,
				goarch,
			))
		}
		fatal(fmt.Errorf("download library: %w", err))
	}
	if err := tmpFile.Close(); err != nil {
		fatal(fmt.Errorf("flush temp file: %w", err))
	}

	gotSHA, err := fileSHA256(tmpPath)
	if err != nil {
		fatal(fmt.Errorf("hash downloaded file: %w", err))
	}
	if !strings.EqualFold(gotSHA, expectedSHA) {
		fatal(fmt.Errorf("checksum mismatch for %s: got %s, expected %s", assetName, gotSHA, expectedSHA))
	}

	if err := os.Rename(tmpPath, targetPath); err != nil {
		fatal(fmt.Errorf("move downloaded file into place: %w", err))
	}

	printResult(targetPath, installDir, printEnvOnly)
}

func printResult(targetPath, installDir string, printEnvOnly bool) {
	envVal := fmt.Sprintf("-L%s", installDir)
	if printEnvOnly {
		if runtime.GOOS == "windows" {
			fmt.Printf("$env:CGO_LDFLAGS=\"%s\"\n", strings.ReplaceAll(envVal, "\"", "`\""))
			return
		}
		fmt.Printf("export CGO_LDFLAGS=%s\n", shellSingleQuote(envVal))
		return
	}

	fmt.Printf("Installed: %s\n", targetPath)
	if runtime.GOOS == "windows" {
		fmt.Printf("PowerShell: $env:CGO_LDFLAGS=\"%s\"\n", envVal)
		fmt.Printf("cmd.exe: set CGO_LDFLAGS=%s\n", envVal)
		return
	}
	fmt.Printf("Run: export CGO_LDFLAGS=\"%s\"\n", envVal)
}

func shellSingleQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "install-lib: %v\n", err)
	os.Exit(1)
}

func platformAssetName(goos, goarch string) (string, error) {
	switch {
	case goos == "linux" && (goarch == "amd64" || goarch == "arm64"):
	case goos == "darwin" && (goarch == "amd64" || goarch == "arm64"):
	default:
		return "", fmt.Errorf("unsupported platform %s/%s", goos, goarch)
	}
	return fmt.Sprintf("libdcap_qvl_%s_%s.a", goos, goarch), nil
}

func defaultInstallDir(version, goos, goarch string) (string, error) {
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolve user cache dir: %w", err)
	}
	return filepath.Join(cacheRoot, "dcap-qvl", version, goos+"_"+goarch), nil
}

func releaseAssetURL(releaseBaseURL, repo, version, assetName string) string {
	return fmt.Sprintf("%s/%s/releases/download/%s/%s", strings.TrimRight(releaseBaseURL, "/"), repo, version, assetName)
}

func releaseLatestAPIURL(apiRoot, repo string) string {
	return fmt.Sprintf("%s/repos/%s/releases/latest", strings.TrimRight(apiRoot, "/"), repo)
}

func fetchLatestReleaseTag(ctx context.Context, client *http.Client, apiRoot, repo string) (string, error) {
	url := releaseLatestAPIURL(apiRoot, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "dcap-qvl-install-lib")
	if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", &httpStatusError{
			URL:        url,
			Status:     resp.Status,
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(body)),
		}
	}

	var payload latestReleaseResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if payload.TagName == "" {
		return "", errors.New("latest release response has empty tag_name")
	}
	return payload.TagName, nil
}

func downloadBytes(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dcap-qvl-install-lib")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, &httpStatusError{
			URL:        url,
			Status:     resp.Status,
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(body)),
		}
	}
	return io.ReadAll(resp.Body)
}

func downloadToWriter(ctx context.Context, client *http.Client, url string, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "dcap-qvl-install-lib")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &httpStatusError{
			URL:        url,
			Status:     resp.Status,
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(body)),
		}
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

func isHTTPStatus(err error, statusCode int) bool {
	var e *httpStatusError
	if !errors.As(err, &e) {
		return false
	}
	return e.StatusCode == statusCode
}

func parseChecksums(data string) (map[string]string, error) {
	result := make(map[string]string)
	for lineNo, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("invalid checksum line %d: %q", lineNo+1, line)
		}
		hash := fields[0]
		if len(hash) != 64 {
			return nil, fmt.Errorf("invalid sha256 length on line %d", lineNo+1)
		}
		name := strings.TrimPrefix(fields[len(fields)-1], "*")
		result[name] = strings.ToLower(hash)
	}
	return result, nil
}

func fileMatchesSHA256(path, expectedSHA string) (bool, error) {
	_, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	got, err := fileSHA256(path)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(got, expectedSHA), nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
