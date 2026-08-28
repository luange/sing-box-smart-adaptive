package v2rayhttp

import (
	"net/http"
	"reflect"

	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/net/http2"
)

func ResetTransport(rawTransport http.RoundTripper) http.RoundTripper {
	switch transport := rawTransport.(type) {
	case *http.Transport:
		transport.CloseIdleConnections()
		return transport.Clone()
	case *http2.Transport:
		// x/net/http2 intentionally keeps its connection pool private and has
		// changed its layout across releases. Use the supported API instead of
		// go:linkname/unsafe field access, which otherwise makes ordinary builds
		// fail as soon as the dependency removes or renames connPool.
		transport.CloseIdleConnections()
		return transport
	default:
		panic(E.New("unknown transport type: ", reflect.TypeOf(transport)))
	}
}
