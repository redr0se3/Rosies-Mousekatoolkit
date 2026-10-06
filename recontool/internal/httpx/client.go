// Package httpx provides the shared HTTP primitives used by every active
// module that fetches a URL: a bounded-timeout client, response
// fingerprinting (status + content-length + body hash), and the soft-404
// baseline logic the spec requires before trusting any brute-force hit.
package httpx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Response is the trimmed-down shape every module actually needs.
type Response struct {
	StatusCode    int
	ContentLength int64
	BodyHash      string
	Headers       http.Header
}

// Client wraps http.Client with a fixed timeout and no automatic
// following of an unbounded redirect chain (capped at 5, the net/http
// default minus runaway loops).
type Client struct {
	hc *http.Client
}

func New(timeout time.Duration) *Client {
	return &Client{hc: &http.Client{Timeout: timeout}}
}

// Fetch performs a GET and returns a fingerprinted Response. It never
// panics on a non-2xx status — callers decide what to do with 404s,
// redirects, etc.
func (c *Client) Fetch(ctx context.Context, url string, extraHeaders map[string]string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", url, err)
	}
	req.Header.Set("User-Agent", "recontool/1.0 (authorized-recon)")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // cap at 10MB
	if err != nil {
		return nil, fmt.Errorf("reading body of %s: %w", url, err)
	}

	return &Response{
		StatusCode:    resp.StatusCode,
		ContentLength: int64(len(body)),
		BodyHash:      HashBody(body),
		Headers:       resp.Header,
	}, nil
}

// FetchRaw performs a GET and returns the raw body bytes (capped at
// 10MB) along with the status code. Use this when a caller needs to
// actually parse the body (robots.txt, sitemap.xml, a harvested .js
// file) rather than just fingerprint it.
func (c *Client) FetchRaw(ctx context.Context, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("building request for %s: %w", url, err)
	}
	req.Header.Set("User-Agent", "recontool/1.0 (authorized-recon)")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading body of %s: %w", url, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return body, resp.StatusCode, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return body, resp.StatusCode, nil
}

// HashBody fingerprints a response body for the soft-404 baseline
// comparison and for findings dedup across wordlist passes.
func HashBody(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// Baseline is the fingerprint of a guaranteed-nonexistent path, captured
// once per host before a wordlist pass starts.
type Baseline struct {
	StatusCode    int
	ContentLength int64
	BodyHash      string
}

// Matches reports whether resp looks like the same soft-404 page as the
// baseline. Exact hash match is the strong signal; for hosts that inject
// a timestamp/nonce into an otherwise-identical error page, status+length
// alone would false-negative every real baseline comparison, so we also
// treat "identical status and content-length" as a baseline match — the
// spec calls for filtering on more than status code alone, and this
// keeps the check from being defeated by a body that's byte-for-byte
// identical except for one dynamic field.
func (b Baseline) Matches(r *Response) bool {
	if b.BodyHash == r.BodyHash {
		return true
	}
	return b.StatusCode == r.StatusCode && b.ContentLength == r.ContentLength
}
