package api

// DefaultParamsURL returns the URL of path on the API host with the client's
// default query parameters, which name the org a request runs as. A
// hand-written call that builds its own request uses it, so that the request
// carries the same org parameters as the generated calls.
func (c *Client) DefaultParamsURL(path string) string {
	return c.defaultParamsURL(path)
}
