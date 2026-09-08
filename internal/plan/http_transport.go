package plan

import "net/http"

func noProxyTransport() http.RoundTripper {
	return noProxyRoundTripper(http.DefaultTransport)
}

func noProxyRoundTripper(roundTripper http.RoundTripper) http.RoundTripper {
	if roundTripper == nil {
		roundTripper = http.DefaultTransport
	}
	transport, ok := roundTripper.(*http.Transport)
	if !ok {
		return roundTripper
	}
	transport = transport.Clone()
	transport.Proxy = nil
	return transport
}
