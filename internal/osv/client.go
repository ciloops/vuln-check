package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	DefaultBaseURL = "https://api.osv.dev"
	batchLimit     = 1000
)

type Client struct {
	BaseURL     string
	HTTP        *http.Client
	Concurrency int
	UserAgent   string
}

func NewClient() *Client {
	return &Client{
		BaseURL:     DefaultBaseURL,
		HTTP:        &http.Client{Timeout: 20 * time.Second},
		Concurrency: 8,
		UserAgent:   "vuln-check",
	}
}

type Vuln struct {
	ID               string         `json:"id"`
	Aliases          []string       `json:"aliases"`
	Summary          string         `json:"summary"`
	Details          string         `json:"details"`
	Modified         string         `json:"modified"`
	Published        string         `json:"published"`
	Withdrawn        string         `json:"withdrawn"`
	Severity         []Severity     `json:"severity"`
	Affected         []Affected     `json:"affected"`
	References       []Reference    `json:"references"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type Affected struct {
	Package  AffectedPackage `json:"package"`
	Ranges   []Range         `json:"ranges"`
	Versions []string        `json:"versions"`
}

type AffectedPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Purl      string `json:"purl"`
}

type Range struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type batchRequest struct {
	Queries []batchQuery `json:"queries"`
}

type batchQuery struct {
	Package batchPackage `json:"package"`
}

type batchPackage struct {
	Purl string `json:"purl"`
}

type batchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

// QueryBatch returns, for each purl (with version), the OSV ids affecting it.
func (c *Client) QueryBatch(ctx context.Context, purls []string) ([][]string, error) {
	out := make([][]string, len(purls))
	for start := 0; start < len(purls); start += batchLimit {
		end := start + batchLimit
		if end > len(purls) {
			end = len(purls)
		}
		req := batchRequest{}
		for _, p := range purls[start:end] {
			req.Queries = append(req.Queries, batchQuery{Package: batchPackage{Purl: p}})
		}
		var resp batchResponse
		if err := c.post(ctx, "/v1/querybatch", req, &resp); err != nil {
			return nil, err
		}
		if len(resp.Results) != end-start {
			return nil, fmt.Errorf("osv querybatch: got %d results for %d queries", len(resp.Results), end-start)
		}
		for i, r := range resp.Results {
			for _, v := range r.Vulns {
				out[start+i] = append(out[start+i], v.ID)
			}
		}
	}
	return out, nil
}

func (c *Client) Vuln(ctx context.Context, id string) (*Vuln, error) {
	var v Vuln
	if err := c.get(ctx, "/v1/vulns/"+id, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

func (c *Client) do(req *http.Request, out any) error {
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("osv %s: %w", req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("osv %s: HTTP %d", req.URL.Path, resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}
