package portmap

type Client struct{}

func NewClient() (*Client, error) {
	return &Client{}, nil
}

func (c *Client) Close() error {
}
