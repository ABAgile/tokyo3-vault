// Package client provides a thin HTTP client for the Vault API.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client wraps http.Client with base URL and auth token.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// New returns a Client pointed at serverURL with the given bearer token.
func New(serverURL, token string) *Client {
	return &Client{
		base:  strings.TrimRight(serverURL, "/"),
		token: token,
		http:  &http.Client{Timeout: 15 * time.Second},
	}
}

// Do performs an authenticated JSON request and decodes the response into out.
// If out is nil the response body is discarded.
func (c *Client) Do(method, path string, body, out any) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, c.base+path, bodyReader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBody, &e)
		if e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// Get is a convenience wrapper for GET requests.
func (c *Client) Get(path string, out any) error {
	return c.Do(http.MethodGet, path, nil, out)
}

// Post is a convenience wrapper for POST requests.
func (c *Client) Post(path string, body, out any) error {
	return c.Do(http.MethodPost, path, body, out)
}

// Put is a convenience wrapper for PUT requests.
func (c *Client) Put(path string, body, out any) error {
	return c.Do(http.MethodPut, path, body, out)
}

// Delete is a convenience wrapper for DELETE requests.
func (c *Client) Delete(path string) error {
	return c.Do(http.MethodDelete, path, nil, nil)
}

// PostText sends a text/plain body and decodes the JSON response into out.
func (c *Client) PostText(path, text string, out any) error {
	req, err := http.NewRequest(http.MethodPost, c.base+path, strings.NewReader(text))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBody, &e)
		if e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// GetText sends a GET request and returns the response body as a plain string.
func (c *Client) GetText(path string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, c.base+path, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error != "" {
			return "", fmt.Errorf("%s", e.Error)
		}
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return string(body), nil
}

// NoAuth performs a request without an Authorization header (for login/signup).
func NoAuth(serverURL, method, path string, body, out any) error {
	c := &Client{
		base: strings.TrimRight(serverURL, "/"),
		http: &http.Client{Timeout: 15 * time.Second},
	}
	return c.Do(method, path, body, out)
}
