// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package portmap

// Client requests port mappings.
type Client struct{}

// NewClient creates a new client.
func NewClient() (*Client, error) {
	return &Client{}, nil
}

// Close closes a client.
func (c *Client) Close() error {
	return nil
}
